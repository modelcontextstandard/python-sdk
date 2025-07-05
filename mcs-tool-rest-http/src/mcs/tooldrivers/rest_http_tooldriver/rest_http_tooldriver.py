from __future__ import annotations

"""
HTTP-based ToolDriver for the Model Context Standard (MCS) using OpenAPI.

* Fetches an OpenAPI spec via HTTP/HTTPS
* Parses the spec to generate a structured list of MCS.Tool objects
* Executes tool calls by mapping tool names (operationId) back to REST calls
* Optional proxy, basic-auth, custom headers, SSL toggle

"""

import base64
import json
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import requests

# ──────────────────────────────────────────────────────────────
#  MCS base classes (adapt import path to your project layout)
# ──────────────────────────────────────────────────────────────
# WICHTIG: MCSToolDriver und die Tool-Datentypen werden jetzt benötigt
from mcs.drivers.core import MCSToolDriver, Tool, ToolParameter, DriverMeta, DriverBinding


# --------------------------------------------------------------------------- #
#                               Metadata                                      #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class _RestHttpMeta(DriverMeta):
    """Static metadata so an orchestrator can pick this driver."""
    id: str = "cb8d5cb9-089d-4b96-8439-1a4cda5f1621"
    name: str = "REST HTTP MCS ToolDriver"
    version: str = "0.1.0"  # Version erhöht, da signifikante Änderung
    bindings: tuple[DriverBinding, ...] = (
        DriverBinding(
            protocol="REST", transport="HTTP", spec_format="OpenAPI"
            )
    ),
    supported_llms: None = None
    capabilities: tuple[str, ...] = ("healthcheck",)


# --------------------------------------------------------------------------- #
#                               ToolDriver                                    #
# --------------------------------------------------------------------------- #
class RestHttpToolDriver(MCSToolDriver):
    """
    Parses an OpenAPI specification to provide structured tools to an LLM.
    """

    meta: DriverMeta = _RestHttpMeta()

    # __init__, _do_request, _initialize_driver bleiben unverändert
    def __init__(
            self,
            url: str,
            *,
            default_headers: Optional[dict[str, str]] = None,
            proxy_url: str | None = None,
            proxy_port: int | None = None,
            proxy_user: str | None = None,
            proxy_password: str | None = None,
            basic_user: str | None = None,
            basic_password: str | None = None,
            verify_ssl: bool = True,
    ) -> None:
        self.spec_url = url
        self.default_headers: dict[str, str] = default_headers or {}
        self.verify_ssl = verify_ssl
        self._tools: List[Tool] | None = None
        self._tool_map: Dict[str, Dict[str, Any]] = {}
        self._base_url: str | None = None
        if proxy_url and proxy_port:
            auth_seg = f"{proxy_user}:{proxy_password}@" if proxy_user and proxy_password else ""
            proxy_base = f"{proxy_url}:{proxy_port}"
            full_proxy = f"http://{auth_seg}{proxy_base}"
            self.proxies = {"http": full_proxy, "https": full_proxy}
        else:
            self.proxies: dict[str, str] | None = None
        if basic_user and basic_password:
            token = base64.b64encode(f"{basic_user}:{basic_password}".encode()).decode()
            self.default_headers.setdefault("Authorization", f"Basic {token}")

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

    def _initialize_driver(self) -> None:
        if self._tools is not None:
            return
        logging.info(f"Initializing RestHttpToolDriver from spec: {self.spec_url}")
        try:
            spec_text = self._do_request("GET", self.spec_url)
            spec = json.loads(spec_text)
        except Exception as e:
            logging.error(f"Failed to fetch or parse OpenAPI spec: {e}")
            self._tools = []
            return
        self._base_url = spec.get("servers", [{}])[0].get("url")
        if not self._base_url:
            parsed = urlparse(self.spec_url)
            self._base_url = f"{parsed.scheme}://{parsed.netloc}"
        self._base_url = self._base_url.rstrip("/")
        self._parse_spec_to_tools(spec)
        if self._tools:
            logging.info(f"Successfully parsed {len(self._tools)} tools.")

    # --------------------------- KORRIGIERTER TEIL -------------------------- #
    def _parse_spec_to_tools(self, spec: Dict[str, Any]) -> None:
        """Iteriert durch die OpenAPI-Pfade und erstellt MCS-Tool-Objekte."""
        tools = []
        for path, path_item in spec.get("paths", {}).items():
            for method, operation in path_item.items():
                if method.lower() not in ["get", "post", "put", "delete", "patch"]:
                    continue
                if "operationId" not in operation:
                    logging.warning(f"Skipping operation {method.upper()} {path} due to missing 'operationId'.")
                    continue

                tool_name = operation["operationId"]
                description = operation.get("summary") or operation.get("description", "No description available.")
                parameters = []

                # Standard-Parameter (query, path, header)
                for param_spec in operation.get("parameters", []):
                    parameters.append(ToolParameter(
                        name=param_spec["name"],
                        description=param_spec.get("description", ""),
                        required=param_spec.get("required", False),
                        # KORREKT: Das 'schema'-Objekt direkt übergeben
                        schema=param_spec.get("schema", {"type": "string"})
                    ))

                # Request-Body (typischerweise für POST/PUT)
                if "requestBody" in operation:
                    content = operation["requestBody"].get("content", {}).get("application/json", {})
                    if "schema" in content:
                        schema = content["schema"]
                        if schema.get("type") == "object" and "properties" in schema:
                            for prop_name, prop_spec in schema["properties"].items():
                                parameters.append(ToolParameter(
                                    name=prop_name,
                                    description=prop_spec.get("description", ""),
                                    required=prop_name in schema.get("required", []),
                                    # KORREKT: Die Eigenschafts-Spezifikation ist das Schema
                                    schema=prop_spec
                                ))

                tool = Tool(name=tool_name, description=description, parameters=parameters)
                tools.append(tool)
                self._tool_map[tool_name] = {
                    "path": path, "method": method.upper(), "spec": operation
                }
        self._tools = tools

    # --------------------------- contract --------------------------------- #
    # list_tools und execute_tool bleiben unverändert
    def list_tools(self) -> List[Tool]:
        """Gibt eine Liste der aus der OpenAPI-Spezifikation geparsten Tools zurück."""
        self._initialize_driver()
        return self._tools or []

    def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> str:
        """Führt ein benanntes Tool aus, indem es eine konfigurierte REST-Anfrage stellt."""
        self._initialize_driver()
        if tool_name not in self._tool_map:
            raise ValueError(f"Tool '{tool_name}' not found in this driver.")

        tool_info = self._tool_map[tool_name]
        method = tool_info["method"]
        path_template = tool_info["path"]
        operation_spec = tool_info["spec"]

        path_params, query_params, body_params = {}, {}, {}
        param_specs = {p["name"]: p.get("in", "body") for p in operation_spec.get("parameters", [])}

        for name, value in arguments.items():
            location = param_specs.get(name, "body")
            if location == "path":
                path_params[name] = value
            elif location == "query":
                query_params[name] = value
            else:
                body_params[name] = value

        final_path = path_template.format(**path_params)
        full_url = urljoin(self._base_url + "/", final_path.lstrip("/"))

        logging.info(f"Executing '{tool_name}': {method} {full_url}")
        logging.debug(f"Query: {query_params}, Body: {body_params}")

        # In der Ausführung müssen wir unterscheiden, ob die Argumente als Query-Parameter
        # oder als JSON-Body gesendet werden sollen.
        if method == "GET":
            return self._do_request("GET", full_url, params=arguments)
        else:
            return self._do_request(method, full_url, json_body=arguments)
