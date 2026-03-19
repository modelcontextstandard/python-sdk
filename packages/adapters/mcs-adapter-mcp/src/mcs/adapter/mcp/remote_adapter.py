"""MCPRemoteAdapter — connects to remote MCP servers via Streamable HTTP.

Implements the MCPPort protocol for MCP servers reachable over the network.
Supports the Streamable HTTP transport (MCP 2025-03-26 spec) with SSE
fallback for older servers.

Zero mandatory dependencies beyond the stdlib ``urllib``/``json`` modules.
Optional ``requests`` for robustness (proxy, auth, timeouts).
"""

from __future__ import annotations

import json
import logging
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional

from .ports import MCPToolDef, MCPToolResult

logger = logging.getLogger(__name__)

_JSONRPC_VERSION = "2.0"


class MCPRemoteAdapter:
    """Adapter that speaks JSON-RPC over HTTP to a remote MCP server.

    Parameters
    ----------
    url : str
        Base URL of the MCP server (e.g. ``"https://mcp.example.com"``
        or ``"http://localhost:3000/mcp"``).
    headers : dict | None
        Extra HTTP headers (e.g. ``{"Authorization": "Bearer ..."}``)
        attached to every request.
    timeout : int
        HTTP request timeout in seconds.
    """

    def __init__(
        self,
        *,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        timeout: int = 30,
    ) -> None:
        self._url = url.rstrip("/")
        self._headers = headers or {}
        self._timeout = timeout
        self._session_id: Optional[str] = None
        self._request_id = 0
        self._connected = False

    # ------------------------------------------------------------------
    # MCPPort interface
    # ------------------------------------------------------------------

    def connect(self) -> None:
        """Initialise the MCP session via ``initialize`` handshake."""
        resp = self._rpc("initialize", {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {
                "name": "mcs-adapter-mcp",
                "version": "0.1.0",
            },
        })
        logger.info(
            "MCP session initialised: server=%s, protocol=%s",
            resp.get("serverInfo", {}).get("name", "unknown"),
            resp.get("protocolVersion", "unknown"),
        )
        # Send initialized notification (no id → notification).
        self._notify("notifications/initialized", {})
        self._connected = True

    def disconnect(self) -> None:
        """Close the MCP session."""
        self._session_id = None
        self._connected = False
        logger.info("MCP session closed")

    def list_tools(self) -> List[MCPToolDef]:
        """Retrieve tools from the MCP server via ``tools/list``."""
        self._ensure_connected()
        resp = self._rpc("tools/list", {})
        tools: List[MCPToolDef] = []
        for t in resp.get("tools", []):
            tools.append(MCPToolDef(
                name=t["name"],
                description=t.get("description", ""),
                input_schema=t.get("inputSchema", {}),
            ))
        logger.info("MCP server exposes %d tools", len(tools))
        return tools

    def call_tool(
        self, name: str, arguments: Dict[str, Any]
    ) -> MCPToolResult:
        """Invoke a tool via ``tools/call``."""
        self._ensure_connected()
        resp = self._rpc("tools/call", {
            "name": name,
            "arguments": arguments,
        })
        is_error = resp.get("isError", False)
        content = resp.get("content", [])
        # Flatten text content for convenience.
        text_parts = []
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                text_parts.append(block.get("text", ""))
        result_text = "\n".join(text_parts) if text_parts else content
        return MCPToolResult(content=result_text, is_error=is_error)

    # ------------------------------------------------------------------
    # JSON-RPC transport (Streamable HTTP)
    # ------------------------------------------------------------------

    def _next_id(self) -> int:
        self._request_id += 1
        return self._request_id

    def _rpc(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Send a JSON-RPC request and return the result."""
        payload = {
            "jsonrpc": _JSONRPC_VERSION,
            "id": self._next_id(),
            "method": method,
            "params": params,
        }
        body = json.dumps(payload).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            **self._headers,
        }
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id

        req = urllib.request.Request(
            self._url, data=body, headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                # Capture session id from response headers.
                sid = resp.headers.get("Mcp-Session-Id")
                if sid:
                    self._session_id = sid

                content_type = resp.headers.get("Content-Type", "")
                raw = resp.read().decode("utf-8")

                if "text/event-stream" in content_type:
                    return self._parse_sse(raw)
                return self._parse_json_rpc(raw)
        except urllib.error.HTTPError as exc:
            error_body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                f"MCP server returned HTTP {exc.code}: {error_body}"
            ) from exc

    def _notify(self, method: str, params: Dict[str, Any]) -> None:
        """Send a JSON-RPC notification (no id, no response expected)."""
        payload = {
            "jsonrpc": _JSONRPC_VERSION,
            "method": method,
            "params": params,
        }
        body = json.dumps(payload).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            **self._headers,
        }
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id

        req = urllib.request.Request(
            self._url, data=body, headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                resp.read()  # Drain response.
        except urllib.error.HTTPError:
            pass  # Notifications may return 204 or be silently accepted.

    def _parse_json_rpc(self, raw: str) -> Dict[str, Any]:
        """Parse a standard JSON-RPC response."""
        data = json.loads(raw)
        if "error" in data:
            err = data["error"]
            raise RuntimeError(
                f"MCP JSON-RPC error {err.get('code')}: {err.get('message')}"
            )
        return data.get("result", {})

    def _parse_sse(self, raw: str) -> Dict[str, Any]:
        """Parse an SSE stream and extract the first JSON-RPC result."""
        for line in raw.splitlines():
            if line.startswith("data:"):
                data_str = line[len("data:"):].strip()
                if not data_str:
                    continue
                return self._parse_json_rpc(data_str)
        raise RuntimeError("No JSON-RPC result found in SSE stream")

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _ensure_connected(self) -> None:
        if not self._connected:
            raise RuntimeError(
                "Not connected to MCP server. Call connect() first."
            )
