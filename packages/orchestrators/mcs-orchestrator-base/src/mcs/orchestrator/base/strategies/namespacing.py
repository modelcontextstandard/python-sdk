"""Namespacing layer.

When more than one driver is registered, tool names are automatically
prefixed as ``{label}__{original_name}`` so the LLM can distinguish
between tools from different connections.  When only a single driver
is registered the prefix is omitted for cleaner prompts.
"""

from __future__ import annotations

from typing import Any

from mcs.driver.core import MCSToolDriver, Tool

from .layer import ToolLayer

NAMESPACE_SEP = "__"


class NamespacingLayer(ToolLayer):
    """Prefix tool names with the driver label when >1 driver is registered."""

    def _use_namespace(self, labeled: dict[str, MCSToolDriver]) -> bool:
        return len(labeled) > 1

    def list_tools(self, labeled: dict[str, MCSToolDriver]) -> list[Tool]:
        tools: list[Tool] = []
        for label, driver in labeled.items():
            for tool in driver.list_tools():
                if self._use_namespace(labeled):
                    ns_name = f"{label}{NAMESPACE_SEP}{tool.name}"
                    desc = f"[{label}] {tool.description}"
                else:
                    ns_name = tool.name
                    desc = tool.description
                tools.append(Tool(
                    name=ns_name,
                    description=desc,
                    parameters=list(tool.parameters),
                ))
        return tools

    def execute_tool(
        self,
        labeled: dict[str, MCSToolDriver],
        tool_name: str,
        arguments: dict[str, Any],
    ) -> Any:
        if self._use_namespace(labeled) and NAMESPACE_SEP in tool_name:
            label, original = tool_name.split(NAMESPACE_SEP, 1)
            driver = labeled.get(label)
            if driver is not None:
                return driver.execute_tool(original, arguments)

        # Single driver or unnamespaced fallback
        return self._inner.execute_tool(labeled, tool_name, arguments)
