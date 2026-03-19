"""MCP ToolDriver — exposes any MCP server's tools as native MCS tools.

Bridges the MCP protocol into the MCS tool ecosystem.  The ToolDriver
connects to an MCP server (remote or local) via an adapter that satisfies
``MCPPort``, retrieves its tool definitions, and translates them into MCS
``Tool`` objects.  Tool calls from the LLM are forwarded to the MCP server
and results are returned as JSON strings.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from mcs.driver.core.mcs_driver_interface import DriverBinding, DriverMeta
from mcs.driver.core.mcs_tool_driver_interface import (
    MCSToolDriver,
    Tool,
    ToolParameter,
)

from mcs.adapter.mcp.ports import MCPPort, MCPToolDef

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class _MCPToolDriverMeta(DriverMeta):
    id: str = "f1e2d3c4-mcp1-4000-a000-mcpbridge00001"
    name: str = "MCP Bridge MCS ToolDriver"
    version: str = "0.1.0"
    bindings: tuple = (
        DriverBinding(
            capability="mcp-bridge", adapter="*", spec_format="MCP"
        ),
    )
    supported_llms: None = None
    capabilities: tuple = ("orchestratable",)


def _mcp_schema_to_parameters(
    input_schema: Dict[str, Any],
) -> List[ToolParameter]:
    """Convert an MCP tool's JSON Schema ``inputSchema`` to MCS ToolParameters."""
    if not input_schema or input_schema.get("type") != "object":
        return []
    properties = input_schema.get("properties", {})
    required = set(input_schema.get("required", []))
    params: List[ToolParameter] = []
    for name, prop in properties.items():
        params.append(ToolParameter(
            name=name,
            description=prop.get("description", ""),
            required=name in required,
            schema=prop,
        ))
    return params


class MCPToolDriver(MCSToolDriver):
    """ToolDriver that wraps an MCP server via the :class:`MCPPort` protocol.

    Parameters
    ----------
    adapter : str
        Backend identifier: ``"remote"`` or ``"local"``.
    server_name : str | None
        Human-readable name for this MCP server (used in logging).
    auto_connect : bool
        If True (default), ``connect()`` is called automatically on
        first tool access.
    _adapter : MCPPort | None
        Pre-built adapter instance (for testing / DI).
    **adapter_kwargs
        Forwarded to the adapter constructor when *_adapter* is None.
    """

    meta: DriverMeta = _MCPToolDriverMeta()

    def __init__(
        self,
        *,
        adapter: str = "remote",
        server_name: Optional[str] = None,
        auto_connect: bool = True,
        _adapter: Optional[MCPPort] = None,
        **adapter_kwargs: Any,
    ) -> None:
        if _adapter is not None:
            self._adapter: MCPPort = _adapter
        elif adapter == "remote":
            from mcs.adapter.mcp import MCPRemoteAdapter

            self._adapter = MCPRemoteAdapter(**adapter_kwargs)
        elif adapter == "local":
            from mcs.adapter.mcp import MCPLocalAdapter

            self._adapter = MCPLocalAdapter(**adapter_kwargs)
        else:
            raise ValueError(
                f"Unknown MCP adapter: {adapter!r}. "
                f"Supported: 'remote', 'local'.  Or pass _adapter directly."
            )

        self._server_name = server_name or adapter
        self._auto_connect = auto_connect
        self._connected = False
        self._cached_tools: Optional[List[MCPToolDef]] = None

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def connect(self) -> None:
        """Explicitly connect to the MCP server."""
        if self._connected:
            return
        self._adapter.connect()
        self._connected = True
        logger.info("MCPToolDriver connected to [%s]", self._server_name)

    def disconnect(self) -> None:
        """Disconnect from the MCP server and release resources."""
        if not self._connected:
            return
        self._adapter.disconnect()
        self._connected = False
        self._cached_tools = None
        logger.info("MCPToolDriver disconnected from [%s]", self._server_name)

    def _ensure_connected(self) -> None:
        if not self._connected:
            if self._auto_connect:
                self.connect()
            else:
                raise RuntimeError(
                    f"Not connected to MCP server [{self._server_name}]. "
                    "Call connect() first."
                )

    # ------------------------------------------------------------------
    # MCSToolDriver interface
    # ------------------------------------------------------------------

    def list_tools(self) -> List[Tool]:
        """Fetch tools from the MCP server and return as MCS Tool objects."""
        self._ensure_connected()
        if self._cached_tools is None:
            self._cached_tools = self._adapter.list_tools()

        tools: List[Tool] = []
        for mcp_tool in self._cached_tools:
            tools.append(Tool(
                name=mcp_tool.name,
                description=mcp_tool.description,
                parameters=_mcp_schema_to_parameters(mcp_tool.input_schema),
            ))
        return tools

    def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """Forward a tool call to the MCP server."""
        self._ensure_connected()
        logger.info(
            "[%s] Calling MCP tool: %s(%s)",
            self._server_name,
            tool_name,
            json.dumps(arguments, default=str)[:200],
        )
        result = self._adapter.call_tool(tool_name, arguments)

        if result.is_error:
            logger.warning(
                "[%s] MCP tool %s returned error: %s",
                self._server_name,
                tool_name,
                str(result.content)[:200],
            )
            return json.dumps({
                "error": True,
                "content": result.content,
            })

        return json.dumps({
            "content": result.content,
        })

    def refresh_tools(self) -> List[Tool]:
        """Force re-fetch of the tool list from the MCP server."""
        self._cached_tools = None
        return self.list_tools()
