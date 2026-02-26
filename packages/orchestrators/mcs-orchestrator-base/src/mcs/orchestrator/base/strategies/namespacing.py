"""Namespacing resolution strategy.

When more than one driver is registered, tool names are automatically
prefixed as ``{label}__{original_name}`` so the LLM can distinguish
between tools from different connections.  When only a single driver
is registered the prefix is omitted for cleaner prompts.
"""

from __future__ import annotations

from mcs.driver.core import MCSToolDriver, Tool

from .strategy import ResolutionStrategy

NAMESPACE_SEP = "__"


class NamespacingStrategy(ResolutionStrategy):
    """Prefix tool names with the driver label when >1 driver is registered."""

    def _use_namespace(self, labeled: dict[str, MCSToolDriver]) -> bool:
        return len(labeled) > 1

    def _namespaced_name(
        self, label: str, tool_name: str, labeled: dict[str, MCSToolDriver],
    ) -> str:
        if self._use_namespace(labeled):
            return f"{label}{NAMESPACE_SEP}{tool_name}"
        return tool_name

    def list_tools(self, labeled: dict[str, MCSToolDriver]) -> list[Tool]:
        tools: list[Tool] = []
        for label, driver in labeled.items():
            for tool in driver.list_tools():
                ns_name = self._namespaced_name(label, tool.name, labeled)
                if self._use_namespace(labeled):
                    desc = f"[{label}] {tool.description}"
                else:
                    desc = tool.description
                tools.append(Tool(
                    name=ns_name,
                    description=desc,
                    parameters=list(tool.parameters),
                ))
        return tools

    def resolve(
        self, labeled: dict[str, MCSToolDriver], tool_name: str,
    ) -> tuple[MCSToolDriver, str]:
        if self._use_namespace(labeled) and NAMESPACE_SEP in tool_name:
            label, original = tool_name.split(NAMESPACE_SEP, 1)
            driver = labeled.get(label)
            if driver is not None:
                return driver, original

        for drv in labeled.values():
            if any(t.name == tool_name for t in drv.list_tools()):
                return drv, tool_name

        raise ValueError(f"No tool '{tool_name}' found across registered drivers.")
