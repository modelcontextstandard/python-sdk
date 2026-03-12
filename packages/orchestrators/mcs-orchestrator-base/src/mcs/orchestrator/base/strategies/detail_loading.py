"""Detail-loading layer.

Abbreviates tool descriptions to a maximum length and injects a
synthetic ``get_tool_details`` tool.  When the LLM needs full
information about a tool it calls ``get_tool_details`` with the
tool name and receives the unabridged description + parameters.
"""

from __future__ import annotations

from typing import Any

from mcs.driver.core import MCSToolDriver, Tool, ToolParameter

from .layer import ToolLayer


class DetailLoadingLayer(ToolLayer):
    """Abbreviated descriptions with on-demand detail loading."""

    def __init__(self, max_desc_length: int = 80, *, inner=None) -> None:
        super().__init__(inner)
        self._max_desc_length = max_desc_length
        self._full_tools: dict[str, Tool] = {}

    def _abbreviate(self, text: str) -> str:
        if len(text) <= self._max_desc_length:
            return text
        return text[: self._max_desc_length - 3] + "..."

    def list_tools(self, labeled: dict[str, MCSToolDriver]) -> list[Tool]:
        all_tools = self._inner.list_tools(labeled)
        self._full_tools = {t.name: t for t in all_tools}
        abbreviated: list[Tool] = []
        for tool in all_tools:
            abbreviated.append(Tool(
                name=tool.name,
                description=self._abbreviate(tool.description),
                parameters=list(tool.parameters),
            ))
        abbreviated.append(Tool(
            name="get_tool_details",
            description="Get full description and parameters for a tool.",
            parameters=[
                ToolParameter(
                    name="tool_name",
                    description="Name of the tool to inspect.",
                    required=True,
                ),
            ],
        ))
        return abbreviated

    def execute_tool(
        self,
        labeled: dict[str, MCSToolDriver],
        tool_name: str,
        arguments: dict[str, Any],
    ) -> Any:
        if tool_name == "get_tool_details":
            target = arguments.get("tool_name", "")
            tool = self._full_tools.get(target)
            if tool is None:
                return {"error": f"Unknown tool: {target}"}
            return {
                "name": tool.name,
                "description": tool.description,
                "parameters": [
                    {
                        "name": p.name,
                        "description": p.description,
                        "required": p.required,
                    }
                    for p in tool.parameters
                ],
            }
        return self._inner.execute_tool(labeled, tool_name, arguments)

    def get_instructions(self) -> str | None:
        return (
            "Tool descriptions may be abbreviated. "
            "Call 'get_tool_details' with a tool name to see its full description and parameters."
        )
