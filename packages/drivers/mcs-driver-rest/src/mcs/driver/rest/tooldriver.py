"""MCS ToolDriver for REST APIs (OpenAPI / Swagger 2.0).

Orchestrator-facing driver that parses OpenAPI specs into structured
``Tool`` objects and executes calls via REST through the HTTP adapter.

* Fetches an OpenAPI or Swagger 2.0 spec via the HTTP adapter
* Swagger 2.0 specs are converted to OpenAPI 3.x on the fly
* Supports JSON and YAML specs (YAML requires ``pyyaml``)
* Resolves ``$ref`` pointers recursively
* Inherits path-level parameters and merges with operation params
* Generates fallback operationIds when missing
* Routes header and cookie parameters correctly
* Supports per-operation server overrides
* Healthcheck via the adapter (spec endpoint reachable?)
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Dict, List
from urllib.parse import urljoin, urlparse

from mcs.driver.core import MCSToolDriver, Tool, ToolParameter, DriverMeta, DriverBinding
from mcs.driver.core.mixins import SupportsHealthcheck, HealthCheckResult, HealthStatus

from .ports import HttpPort

try:
    import yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class _RestToolMeta(DriverMeta):
    id: str = "cb8d5cb9-089d-4b96-8439-1a4cda5f1621"
    name: str = "REST MCS ToolDriver"
    version: str = "0.2.0"
    bindings: tuple[DriverBinding, ...] = (
        DriverBinding(capability="rest", adapter="http", spec_format="OpenAPI"),
    )
    supported_llms: None = None
    capabilities: tuple[str, ...] = ("orchestratable", "healthcheck")


class RestToolDriver(MCSToolDriver, SupportsHealthcheck):
    """Parses an OpenAPI specification to provide structured tools to an orchestrator.

    The ToolDriver owns the adapter and is the only layer that knows about
    the transport.  Everything above (Driver, Orchestrator) sees only
    ``list_tools()`` and ``execute_tool()``.
    """

    meta: DriverMeta = _RestToolMeta()

    def __init__(
        self,
        url: str,
        *,
        include_tags: List[str] | None = None,
        include_paths: List[str] | None = None,
        _http: HttpPort | None = None,
        **http_kwargs: Any,
    ) -> None:
        self.spec_url = url
        self._include_tags = {t.lower() for t in include_tags} if include_tags else None
        self._include_paths = set(include_paths) if include_paths else None
        if _http is not None:
            self._http: HttpPort = _http
        else:
            from mcs.adapter.http import HttpAdapter
            self._http = HttpAdapter(**http_kwargs)
        self._tools: List[Tool] | None = None
        self._tool_map: Dict[str, Dict[str, Any]] = {}
        self._base_url: str | None = None

    # -- SupportsHealthcheck --------------------------------------------------

    def healthcheck(self) -> HealthCheckResult:
        try:
            self._http.head(self.spec_url, timeout=5)
            return {"status": HealthStatus.OK}
        except Exception as e:
            return {"status": HealthStatus.ERROR, "detail": f"unreachable: {e}"}  # type: ignore[typeddict-item]

    # -- spec parsing helpers -------------------------------------------------

    @staticmethod
    def _parse_raw_spec(text: str) -> Dict[str, Any]:
        """Parse spec text as JSON; fall back to YAML if pyyaml is installed."""
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            if _HAS_YAML:
                return yaml.safe_load(text)
            raise ValueError(
                "Spec is not valid JSON and pyyaml is not installed. "
                "Install pyyaml (`pip install pyyaml`) for YAML spec support."
            )

    @staticmethod
    def _convert_swagger2(spec: Dict[str, Any]) -> Dict[str, Any]:
        """Best-effort conversion of a Swagger 2.0 spec to OpenAPI 3.x shape."""
        host = spec.get("host", "localhost")
        schemes = spec.get("schemes", ["https"])
        base_path = spec.get("basePath", "/")
        base_url = f"{schemes[0]}://{host}{base_path}".rstrip("/")

        out: Dict[str, Any] = {
            "openapi": "3.0.0",
            "info": spec.get("info", {}),
            "servers": [{"url": base_url}],
            "paths": {},
        }

        if "definitions" in spec:
            out.setdefault("components", {})["schemas"] = spec["definitions"]

        for path, path_item in spec.get("paths", {}).items():
            new_item: Dict[str, Any] = {}
            path_params = path_item.get("parameters", [])
            if path_params:
                new_item["parameters"] = path_params

            for method, operation in path_item.items():
                if method == "parameters" or method.startswith("x-"):
                    continue
                if not isinstance(operation, dict):
                    continue

                new_op: Dict[str, Any] = {
                    k: v for k, v in operation.items() if k != "parameters"
                }
                new_params: list = []
                for p in operation.get("parameters", []):
                    if p.get("in") == "body":
                        schema = p.get("schema", {})
                        new_op["requestBody"] = {
                            "content": {"application/json": {"schema": schema}},
                            "required": p.get("required", False),
                        }
                    elif p.get("in") == "formData":
                        continue
                    else:
                        if "type" in p and "schema" not in p:
                            p = {**p, "schema": {"type": p.pop("type")}}
                        new_params.append(p)
                new_op["parameters"] = new_params
                new_item[method] = new_op
            out["paths"][path] = new_item

        raw = json.dumps(out)
        raw = raw.replace("#/definitions/", "#/components/schemas/")
        return json.loads(raw)

    def _resolve_ref(self, obj: Any, spec: Dict[str, Any]) -> Any:
        """Recursively resolve $ref pointers against the root spec."""
        if isinstance(obj, dict):
            if "$ref" in obj:
                ref_path = obj["$ref"]
                if ref_path.startswith("#/"):
                    parts = ref_path[2:].split("/")
                    resolved = spec
                    for part in parts:
                        resolved = resolved.get(part, {})
                    return self._resolve_ref(resolved, spec)
                return obj
            return {k: self._resolve_ref(v, spec) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._resolve_ref(item, spec) for item in obj]
        return obj

    @staticmethod
    def _generate_operation_id(method: str, path: str) -> str:
        """Generate a tool name from method + path when operationId is missing."""
        clean = path.strip("/").replace("/", "_").replace("{", "").replace("}", "")
        return f"{method.lower()}_{clean}"

    @staticmethod
    def _sanitize_tool_name(name: str) -> str:
        """Ensure tool names match ``^[a-zA-Z0-9_-]+$`` (required by OpenAI)."""
        import re
        return re.sub(r"[^a-zA-Z0-9_-]", "_", name)

    # -- initialization -------------------------------------------------------

    def _initialize(self) -> None:
        if self._tools is not None:
            return
        logger.info("Fetching OpenAPI spec from %s", self.spec_url)
        try:
            spec_text = self._http.request("GET", self.spec_url)
            spec = self._parse_raw_spec(spec_text)
        except Exception as e:
            logger.error("Failed to fetch or parse OpenAPI spec: %s", e)
            self._tools = []
            return

        if spec.get("swagger", "").startswith("2"):
            spec = self._convert_swagger2(spec)

        raw_server_url = spec.get("servers", [{}])[0].get("url", "")
        if raw_server_url and "://" in raw_server_url:
            self._base_url = raw_server_url
        else:
            parsed = urlparse(self.spec_url)
            origin = f"{parsed.scheme}://{parsed.netloc}"
            self._base_url = origin + raw_server_url if raw_server_url else origin
        self._base_url = self._base_url.rstrip("/")
        self._parse_spec(spec)
        if self._tools:
            logger.info("Parsed %d tools from spec.", len(self._tools))

    def _matches_filter(self, path: str, operation: Dict[str, Any]) -> bool:
        """Return True if the operation passes include_paths / include_tags."""
        if self._include_paths is not None:
            if path not in self._include_paths:
                return False
        if self._include_tags is not None:
            op_tags = {t.lower() for t in operation.get("tags", [])}
            if not op_tags & self._include_tags:
                return False
        return True

    def _parse_spec(self, spec: Dict[str, Any]) -> None:
        tools: list[Tool] = []
        for path, raw_path_item in spec.get("paths", {}).items():
            path_item = self._resolve_ref(raw_path_item, spec)
            path_level_params = path_item.get("parameters", [])

            for method, raw_operation in path_item.items():
                if method.lower() not in ("get", "post", "put", "delete", "patch"):
                    continue

                operation = self._resolve_ref(raw_operation, spec)

                if not self._matches_filter(path, operation):
                    continue
                tool_name = self._sanitize_tool_name(
                    operation.get("operationId")
                    or self._generate_operation_id(method, path)
                )
                title = operation.get("summary") or None
                description = operation.get("description") or title or "No description available."
                parameters: list[ToolParameter] = []

                op_params = operation.get("parameters", [])
                op_param_names = {p["name"] for p in op_params if "name" in p}
                merged_params = op_params + [
                    p
                    for p in path_level_params
                    if p.get("name") not in op_param_names
                ]

                for param_spec in merged_params:
                    parameters.append(
                        ToolParameter(
                            name=param_spec["name"],
                            description=param_spec.get("description", ""),
                            required=param_spec.get("required", False),
                            schema=param_spec.get("schema", {"type": "string"}),
                        )
                    )

                if "requestBody" in operation:
                    req_body = operation["requestBody"]
                    json_content = (
                        req_body.get("content", {}).get("application/json", {})
                    )
                    body_schema = json_content.get("schema", {})
                    if (
                        body_schema.get("type") == "object"
                        and "properties" in body_schema
                    ):
                        required_props = body_schema.get("required", [])
                        for prop_name, prop_spec in body_schema[
                            "properties"
                        ].items():
                            parameters.append(
                                ToolParameter(
                                    name=prop_name,
                                    description=prop_spec.get("description", ""),
                                    required=prop_name in required_props,
                                    schema=prop_spec,
                                )
                            )

                op_server = (
                    operation.get("servers", [{}])[0].get("url")
                    or path_item.get("servers", [{}])[0].get("url")
                    or None
                )

                tools.append(
                    Tool(
                        name=tool_name,
                        description=description,
                        parameters=parameters,
                        title=title,
                    )
                )
                self._tool_map[tool_name] = {
                    "path": path,
                    "method": method.upper(),
                    "spec": operation,
                    "server": op_server,
                }
        self._tools = tools

    # -- MCSToolDriver contract -----------------------------------------------

    def list_tools(self) -> List[Tool]:
        self._initialize()
        return self._tools or []

    def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> str:
        self._initialize()
        if tool_name not in self._tool_map:
            raise ValueError(f"Tool '{tool_name}' not found.")

        tool_info = self._tool_map[tool_name]
        method = tool_info["method"]
        path_template = tool_info["path"]
        operation_spec = tool_info["spec"]

        path_params: Dict[str, Any] = {}
        query_params: Dict[str, Any] = {}
        header_params: Dict[str, str] = {}
        cookie_params: Dict[str, str] = {}
        body_params: Dict[str, Any] = {}

        param_locations = {
            p["name"]: p.get("in", "query")
            for p in operation_spec.get("parameters", [])
        }

        for name, value in arguments.items():
            location = param_locations.get(name)
            if location == "path":
                path_params[name] = value
            elif location == "query":
                query_params[name] = value
            elif location == "header":
                header_params[name] = str(value)
            elif location == "cookie":
                cookie_params[name] = str(value)
            else:
                body_params[name] = value

        final_path = path_template.format(**path_params)
        base = (tool_info.get("server") or self._base_url).rstrip("/")
        full_url = urljoin(base + "/", final_path.lstrip("/"))

        extra_headers: Dict[str, str] | None = header_params or None
        if cookie_params:
            cookie_str = "; ".join(f"{k}={v}" for k, v in cookie_params.items())
            extra_headers = extra_headers or {}
            extra_headers["Cookie"] = cookie_str

        logger.info("Executing '%s': %s %s", tool_name, method, full_url)

        if method == "GET":
            return self._http.request(
                "GET", full_url, params=query_params, headers=extra_headers
            )
        return self._http.request(
            method,
            full_url,
            params=query_params,
            json_body=body_params,
            headers=extra_headers,
        )
