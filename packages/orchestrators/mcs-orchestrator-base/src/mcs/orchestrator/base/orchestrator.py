"""MCS Base Orchestrator -- generic multi-driver orchestrator.

Manages multiple ``MCSToolDriver`` instances at runtime, each identified
by a human-readable *label*.  Tool resolution (namespacing, switching,
etc.) is delegated to a pluggable ``ResolutionStrategy``.

Inherits prompt generation and LLM response parsing from ``DriverBase``.
Uses ``UnknownToolBehavior.RETRY_WITH_LIST`` so the LLM gets feedback
when it calls a tool that does not exist.

**Thread-safety:** All mutations and reads of the internal driver registry
are protected by a ``threading.RLock``.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from typing import Any

from mcs.driver.core import (
    DriverBase,
    MCSToolDriver,
    Tool,
    DriverMeta,
    DriverBinding,
    PromptStrategy,
    JsonPromptStrategy,
    UnknownToolBehavior,
)

from .strategies import ResolutionStrategy, NamespacingStrategy

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class _BaseOrchestratorMeta(DriverMeta):
    id: str = "e7f3a1b2-orch-4000-9000-baseorch00001"
    name: str = "MCS Base Orchestrator"
    version: str = "0.1.0"
    bindings: tuple[DriverBinding, ...] = ()
    supported_llms: tuple[str, ...] = ("*",)
    capabilities: tuple[str, ...] = ("standalone", "orchestratable")


class BaseOrchestrator(DriverBase):
    """Generic multi-driver orchestrator with pluggable resolution strategy.

    Any ``MCSToolDriver`` can be registered via :meth:`add_driver`.
    Tool resolution (namespacing, switching, etc.) is handled by the
    ``ResolutionStrategy`` passed at construction time.

    The orchestrator is **composable**: because it implements
    ``MCSToolDriver`` (via ``DriverBase``), it can itself be embedded
    in another orchestrator.
    """

    meta: DriverMeta = _BaseOrchestratorMeta()

    def __init__(
        self,
        *,
        resolution_strategy: ResolutionStrategy | None = None,
        prompt_strategy: PromptStrategy | None = None,
    ) -> None:
        ps = prompt_strategy or JsonPromptStrategy.from_defaults()
        if isinstance(ps, JsonPromptStrategy):
            ps.unknown_tool_behavior = UnknownToolBehavior.RETRY_WITH_LIST
        super().__init__(prompt_strategy=ps)
        self._resolution = resolution_strategy or NamespacingStrategy()
        self._labeled: dict[str, MCSToolDriver] = {}
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Dynamic driver management
    # ------------------------------------------------------------------

    def add_driver(self, driver: MCSToolDriver, *, label: str) -> None:
        """Register a ``MCSToolDriver`` under *label*.

        Raises ``ValueError`` if *label* is already in use.
        """
        with self._lock:
            if label in self._labeled:
                raise ValueError(f"Label already in use: {label!r}")
            self._labeled[label] = driver
        logger.info("Driver registered: label=%s, name=%s", label, driver.meta.name)

    def remove_driver(self, label: str) -> MCSToolDriver | None:
        """Unregister and return the driver stored under *label*.

        Returns ``None`` if the label was not found.
        """
        with self._lock:
            driver = self._labeled.pop(label, None)
            if driver is not None:
                logger.info("Driver removed: label=%s", label)
            return driver

    @property
    def labels(self) -> list[str]:
        """Return the labels of all registered drivers."""
        with self._lock:
            return list(self._labeled.keys())

    @property
    def resolution_strategy(self) -> ResolutionStrategy:
        """The active resolution strategy (for strategy-specific methods)."""
        return self._resolution

    # ------------------------------------------------------------------
    # MCSToolDriver (orchestratable / composable)
    # ------------------------------------------------------------------

    def list_tools(self) -> list[Tool]:
        with self._lock:
            return self._resolution.list_tools(self._labeled)

    def execute_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        with self._lock:
            driver, original_name = self._resolution.resolve(
                self._labeled, tool_name,
            )
        return driver.execute_tool(original_name, arguments)
