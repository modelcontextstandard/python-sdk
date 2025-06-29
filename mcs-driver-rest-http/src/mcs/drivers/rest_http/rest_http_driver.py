from __future__ import annotations

"""
HTTP-based reference driver for the Model Context Standard (MCS).

* Fetches an OpenAPI (or any JSON) spec via HTTP/HTTPS
* Executes structured REST calls (GET/POST) emitted by an LLM
* Optional proxy, basic-auth, custom headers, SSL toggle
* Supports developer overrides for
  - custom tool description
  - custom system-prompt template

"""

import base64
import json
import logging
import re
from dataclasses import dataclass
from typing import Any, Dict, Optional
from urllib.parse import urljoin, urlparse

import requests

# ──────────────────────────────────────────────────────────────
#  MCS base classes (adapt import path to your project layout)
# ──────────────────────────────────────────────────────────────
from mcs.drivers.core import MCSDriver, DriverMeta  # noqa: F401

# --------------------------------------------------------------------------- #
#                               Metadata                                      #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class _RestHttpMeta(DriverMeta):
    """Static metadata so an orchestrator can pick this driver."""
    id: str = "42144fa5-ed09-4c63-be1f-48122847835a"
    name: str = "REST HTTP Driver"
    version: str = "0.1.0"
    protocol: str = "REST"
    transport: str = "HTTP"
    spec_format: str = "OpenAPI"
    target_llms: tuple[str, ...] = ("*",)  # generic prompt works everywhere
    capabilities: tuple[str, ...] = ("healthcheck")


# --------------------------------------------------------------------------- #
#                               Driver                                        #
# --------------------------------------------------------------------------- #
class RestHttpDriver(MCSDriver):
    """Reference driver: REST over HTTP with OpenAPI discovery."""

    meta: DriverMeta = _RestHttpMeta()

    # ----------------------------- init ----------------------------------- #
    def __init__(
        self,
        urls: list[str],
        *,
        reduced_spec: bool = False,
        default_headers: Optional[dict[str, str]] = None,
        proxy_url: str | None = None,
        proxy_port: int | None = None,
        proxy_user: str | None = None,
        proxy_password: str | None = None,
        basic_user: str | None = None,
        basic_password: str | None = None,
        verify_ssl: bool = True,
        # developer overrides
        custom_tool_description: str | None = None,
        custom_driver_system_message: str | None = None,
    ) -> None:
        self.function_desc_urls = urls
        self.reduced_spec = reduced_spec
        self.default_headers: dict[str, str] = default_headers or {}
        self.verify_ssl = verify_ssl

        # store developer overrides
        self._custom_tool_description = custom_tool_description
        self._custom_system_message = custom_driver_system_message

        # proxy handling
        if proxy_url and proxy_port:
            auth_seg = f"{proxy_user}:{proxy_password}@" if proxy_user and proxy_password else ""
            proxy_base = f"{proxy_url}:{proxy_port}"
            full_proxy = f"http://{auth_seg}{proxy_base}"
            self.proxies = {"http": full_proxy, "https": full_proxy}
        else:
            self.proxies: dict[str, str] | None = None

        # basic auth header
        if basic_user and basic_password:
            token = base64.b64encode(f"{basic_user}:{basic_password}".encode()).decode()
            self.default_headers.setdefault("Authorization", f"Basic {token}")

    # --------------------------- helpers ---------------------------------- #
    def _do_request(
        self,
        method: str,
        url: str,
        *,
        params: Dict[str, Any] | None = None,
        json_body: Dict[str, Any] | None = None,
        headers: Dict[str, str] | None = None,
    ) -> str:
        merged = {**self.default_headers, **(headers or {})}
        resp = requests.request(
            method.upper(),
            url,
            params=params,
            json=json_body,
            headers=merged,
            timeout=15,
            verify=self.verify_ssl,
            proxies=self.proxies,
        )
        resp.raise_for_status()
        return resp.text

    def _reduce_spec(self, spec_text: str) -> str:
        """Optional: strip components and 4xx/5xx responses to keep the spec tiny."""
        try:
            spec = json.loads(spec_text)
        except Exception:
            return spec_text  # not JSON

        spec.pop("components", None)

        for path_item in spec.get("paths", {}).values():
            for op in path_item.values():
                if not isinstance(op, dict):
                    continue
                responses = op.get("responses", {})
                for code in list(responses):
                    if not str(code).startswith(("2", "3")):
                        responses.pop(code, None)
        return json.dumps(spec)

    @staticmethod
    def _extract_json(raw: str) -> str | None:
        """Return first JSON object in `raw`, stripping markdown fences."""
        try:
            if raw.strip().startswith("```"):
                raw = re.sub(r"^```[^\n]*\n", "", raw.strip())
                raw = re.sub(r"\n```$", "", raw)
            match = re.search(r"\{.*\}", raw, re.S)
            return match.group(0) if match else None
        except Exception as e:
            logging.error(f"Error extracting JSON: {e}")
            return None

    # --------------------------- contract --------------------------------- #
    def get_function_description(self, model_name: str | None = None) -> str:
        """Return OpenAPI (or custom) spec. Custom override wins."""
        if self._custom_tool_description is not None:
            return self._custom_tool_description

        spec_text = self._do_request("GET", self.function_desc_urls[0])
        return self._reduce_spec(spec_text) if self.reduced_spec else spec_text

    def get_driver_system_message(self) -> str:
        # TODO Improvment needed for more server that the LLM should use.
        system_message = (
            "You are a helpful assistant with access to these tools:\n\n"
            f"{self.get_function_description()}\n"
            "Choose the appropriate tool based on the user's question. "
            "If no tool is needed, reply directly.\n\n"
            "IMPORTANT: When you need to use a tool, you must ONLY respond with "
            "the exact JSON object format below, nothing else:\n"
            "{\n"
            '    "path": "path-name",\n'
            '    "arguments": {\n'
            '        "argument-name": "value"\n'
            "    }\n"
            "}\n\n"
            "After receiving a tool's response:\n"
            "1. Transform the raw data into a natural, conversational response\n"
            "2. Keep responses concise but informative\n"
            "3. Focus on the most relevant information\n"
            "4. Use appropriate context from the user's question\n"
            "5. Avoid simply repeating the raw data\n\n"
            "Please use only the tools that are explicitly defined above."
            "If you want to use a tool ALWAYS, reply with the JSON object format.\n")
        return system_message

    def process_llm_response(self, llm_response: str) -> str:
        """
        Take the raw LLM output, execute the requested tool and
        return the textual result.

        Expected JSON from the model:
        {
            "path": "/tools/fibonacci",
            "method": "GET",          # optional, defaults to GET
            "arguments": { "n": 4 },  # mapped to query or JSON body
            "headers":   { ... }      # optional
        }
        """

        json_block = self._extract_json(llm_response)
        if not json_block:
            return llm_response  # treat as plain text

        try:
            call = json.loads(json_block)
        except json.JSONDecodeError:
            logging.error("Failed to parse LLM response as JSON.")
            return llm_response

        path = call.get("path")
        method = call.get("method", "GET").upper()
        args = call.get("arguments", {}) or {}
        headers = call.get("headers", {}) or {}
        if not path:
            logging.error("Failed to parse LLM response. No Path given.")
            return llm_response

        logging.info(f"Executing tool: {call.get('path', 'unknown')} ")
        logging.info(f"With arguments: {call.get('arguments', {})} ")

        # derive base URL from spec "servers" or spec URL itself
        if not hasattr(self, "_base_url"):
            try:
                spec_json = json.loads(self.get_function_description())
                base = spec_json.get("servers", [{}])[0].get("url")
            except Exception:
                base = None
            if not base:
                parsed = urlparse(self.function_desc_urls[0])
                base = f"{parsed.scheme}://{parsed.netloc}"
            self._base_url = base.rstrip("/")

        full_url = urljoin(self._base_url + "/", path.lstrip("/"))
        if method == "GET":
            result_text = self._do_request("GET", full_url, params=args, headers=headers)
        else:
            result_text = self._do_request("POST", full_url, json_body=args, headers=headers)

        logging.info(f"Tool response: {result_text[:100]}...")

        return result_text
