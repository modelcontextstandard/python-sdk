"""Resolution strategy interface for orchestrators.

A ``ResolutionStrategy`` controls how an orchestrator exposes and
dispatches tools when multiple drivers are registered.

Concrete implementations shipped with this package:

- ``NamespacingStrategy`` -- prefixes tool names with the driver label
  when more than one driver is registered.
- ``ToolSwitchingStrategy`` -- only one driver is active at a time;
  the caller switches explicitly via ``set_active(label)``.

Future strategies (not yet implemented):

- **PriorityRoutingStrategy** -- all tools visible, name collisions
  resolved by driver priority (higher wins).
- **ContextRoutingStrategy** -- orchestrator selects the appropriate
  driver automatically based on request context.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from mcs.driver.core import MCSToolDriver, Tool


class ResolutionStrategy(ABC):
    """Decides how tool names are presented and dispatched."""

    @abstractmethod
    def list_tools(self, labeled: dict[str, MCSToolDriver]) -> list[Tool]:
        """Return the aggregated tool list for the LLM."""

    @abstractmethod
    def resolve(
        self, labeled: dict[str, MCSToolDriver], tool_name: str,
    ) -> tuple[MCSToolDriver, str]:
        """Map *tool_name* to ``(driver, original_tool_name)``.

        Raises ``ValueError`` when no matching driver is found.
        """
