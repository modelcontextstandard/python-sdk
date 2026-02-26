"""Tool-switching resolution strategy.

Only one driver is active at any time.  The caller switches explicitly
via ``set_active(label)``.  ``list_tools()`` exposes only the active
driver's tools; ``resolve()`` searches only the active driver.
"""

from __future__ import annotations

from mcs.driver.core import MCSToolDriver, Tool

from .strategy import ResolutionStrategy


class ToolSwitchingStrategy(ResolutionStrategy):
    """Only the active driver's tools are visible."""

    def __init__(self) -> None:
        self._active_label: str | None = None

    @property
    def active_label(self) -> str | None:
        return self._active_label

    def set_active(self, label: str) -> None:
        """Set the active driver by *label*.

        Validation against the actual driver registry happens at
        resolution time, not here, so the strategy stays stateless
        with respect to the registry.
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

    def resolve(
        self, labeled: dict[str, MCSToolDriver], tool_name: str,
    ) -> tuple[MCSToolDriver, str]:
        _, driver = self._active_driver(labeled)
        if any(t.name == tool_name for t in driver.list_tools()):
            return driver, tool_name
        raise ValueError(
            f"Tool '{tool_name}' not found in active driver "
            f"'{self._active_label}'."
        )
