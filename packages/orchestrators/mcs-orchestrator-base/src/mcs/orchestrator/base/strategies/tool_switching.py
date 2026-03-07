"""Tool-switching layer.

Only one driver is active at any time.  The caller switches explicitly
via ``set_active(label)``.  ``list_tools()`` exposes only the active
driver's tools; ``execute_tool()`` dispatches only to the active driver.
"""

from __future__ import annotations

from typing import Any

from mcs.driver.core import MCSToolDriver, Tool

from .layer import ToolLayer


class ToolSwitchingLayer(ToolLayer):
    """Only the active driver's tools are visible."""

    def __init__(self, inner=None) -> None:
        super().__init__(inner)
        self._active_label: str | None = None

    @property
    def active_label(self) -> str | None:
        return self._active_label

    def set_active(self, label: str) -> None:
        """Set the active driver by *label*.

        Validation against the actual driver registry happens at
        execution time, not here, so the layer stays stateless with
        respect to the registry.
        """
        self._active_label = label

    def _active_driver(
        self, labeled: dict[str, MCSToolDriver],
    ) -> tuple[str, MCSToolDriver]:
        if self._active_label is None:
            if len(labeled) == 1:
                label = next(iter(labeled))
                return label, labeled[label]
            raise ValueError(
                "No active driver set. Call set_active(label) first."
            )
        driver = labeled.get(self._active_label)
        if driver is None:
            raise ValueError(
                f"Active label '{self._active_label}' not found in registry."
            )
        return self._active_label, driver

    def list_tools(self, labeled: dict[str, MCSToolDriver]) -> list[Tool]:
        _, driver = self._active_driver(labeled)
        return driver.list_tools()

    def execute_tool(
        self,
        labeled: dict[str, MCSToolDriver],
        tool_name: str,
        arguments: dict[str, Any],
    ) -> Any:
        _, driver = self._active_driver(labeled)
        if any(t.name == tool_name for t in driver.list_tools()):
            return driver.execute_tool(tool_name, arguments)
        raise ValueError(
            f"Tool '{tool_name}' not found in active driver "
            f"'{self._active_label}'."
        )
