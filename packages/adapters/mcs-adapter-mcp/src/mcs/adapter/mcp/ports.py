"""MCP port — backend-agnostic interface for MCP server communication.

Any adapter that satisfies this protocol can bridge an MCP server into MCS:
remote (HTTP/SSE), local (subprocess stdio), or containerised (Docker + stdio).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable


@dataclass
class MCPToolDef:
    """A single tool definition received from an MCP server.

    Maps directly to the MCP ``tools/list`` response schema.
    """

    name: str
    description: str = ""
    input_schema: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MCPToolResult:
    """Result of calling a tool on an MCP server.

    Maps to the MCP ``tools/call`` response.
    """

    content: Any = None
    is_error: bool = False


@runtime_checkable
class MCPPort(Protocol):
    """Contract that every MCP backend adapter must satisfy."""

    def connect(self) -> None:
        """Establish the connection to the MCP server.

        For remote servers this opens an HTTP/SSE session.
        For local servers this spawns the subprocess (or Docker container).
        """
        ...

    def disconnect(self) -> None:
        """Tear down the connection and clean up resources."""
        ...

    def list_tools(self) -> List[MCPToolDef]:
        """Retrieve all available tools from the MCP server.

        Returns a list of tool definitions as reported by ``tools/list``.
        """
        ...

    def call_tool(
        self, name: str, arguments: Dict[str, Any]
    ) -> MCPToolResult:
        """Invoke a tool on the MCP server.

        Parameters
        ----------
        name : str
            The tool name as returned by ``list_tools()``.
        arguments : dict
            Tool arguments matching the tool's ``input_schema``.

        Returns
        -------
        MCPToolResult
            The tool execution result (content + error flag).
        """
        ...
