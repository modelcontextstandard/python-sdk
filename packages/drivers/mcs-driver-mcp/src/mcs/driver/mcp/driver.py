"""MCP Driver — LLM-facing wrapper around the MCPToolDriver.

This hybrid driver (``DriverBase`` + ``MCSToolDriver``) can be used
standalone (direct LLM conversation) or nested inside an Orchestrator.
It bridges any MCP server into the MCS ecosystem, making MCP tools
available as native MCS tools.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from mcs.driver.core.base import DriverBase
from mcs.driver.core.mcs_driver_interface import DriverBinding, DriverMeta
from mcs.driver.core.mcs_tool_driver_interface import MCSToolDriver, Tool
from mcs.driver.core.prompt_strategy import PromptStrategy


@dataclass(frozen=True)
class _MCPDriverMeta(DriverMeta):
    id: str = "f1e2d3c4-mcp2-4000-a000-mcpbridge00002"
    name: str = "MCP Bridge MCS Driver"
    version: str = "0.1.0"
    bindings: tuple = (
        DriverBinding(
            capability="mcp-bridge", adapter="*", spec_format="MCP"
        ),
    )
    supported_llms: tuple = ("*",)
    capabilities: tuple = ("standalone", "orchestratable")


class MCPDriver(DriverBase):
    """Full MCS Driver that bridges an MCP server into the MCS world.

    Parameters
    ----------
    adapter : str
        Backend identifier (``"remote"``, ``"local"``).
    server_name : str | None
        Human-readable name for this MCP server.
    auto_connect : bool
        If True, the adapter connects automatically on first tool access.
    custom_tool_description : str | None
        Override the auto-generated tool description.
    custom_driver_system_message : str | None
        Override the default system message.
    prompt_strategy : PromptStrategy | None
        Custom prompt codec.
    _tooldriver : MCSToolDriver | None
        Pre-built ToolDriver (for testing / DI).
    **adapter_kwargs
        Forwarded to the adapter constructor.
    """

    meta: DriverMeta = _MCPDriverMeta()

    def __init__(
        self,
        *,
        adapter: str = "remote",
        server_name: Optional[str] = None,
        auto_connect: bool = True,
        custom_tool_description: Optional[str] = None,
        custom_driver_system_message: Optional[str] = None,
        prompt_strategy: Optional[PromptStrategy] = None,
        _tooldriver: Optional[MCSToolDriver] = None,
        **adapter_kwargs: Any,
    ) -> None:
        super().__init__(
            prompt_strategy=prompt_strategy,
            custom_tool_description=custom_tool_description,
            custom_system_message=custom_driver_system_message,
        )
        if _tooldriver is not None:
            self._td = _tooldriver
        else:
            from mcs.driver.mcp.tooldriver import MCPToolDriver

            self._td = MCPToolDriver(
                adapter=adapter,
                server_name=server_name,
                auto_connect=auto_connect,
                **adapter_kwargs,
            )

    # -- Delegate to ToolDriver -------------------------------------------

    def list_tools(self) -> List[Tool]:
        return self._td.list_tools()

    def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        return self._td.execute_tool(tool_name, arguments)
