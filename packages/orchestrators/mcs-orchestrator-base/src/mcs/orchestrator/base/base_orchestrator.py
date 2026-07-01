"""MCS Base Orchestrator -- generic multi-driver orchestrator.

Manages multiple ``MCSToolDriver`` instances at runtime, each identified
by a human-readable *label*.  Tool listing and execution are delegated
to a pluggable ``ResolutionStrategy`` (typically a ``ToolPipeline``
composed of ``ToolLayer`` decorators).

Inherits prompt generation and LLM response parsing from ``BaseDriver``.
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
    BaseDriver,
    MCSToolDriver,
    Tool,
    DriverMeta,
    DriverBinding,
    PromptStrategy,
    JsonPromptStrategy,
    UnknownToolBehavior,
)
from mcs.driver.core.mixins.healthcheck import (
    SupportsHealthcheck,
    HealthStatus,
    HealthCheckResult,
)

from .strategies import ResolutionStrategy, NamespacingLayer, ToolPipeline

logger = logging.getLogger(__name__)

# Health severity ranking for the default AND-aggregation (higher = worse).
_HEALTH_SEVERITY = {
    HealthStatus.OK: 0,
    HealthStatus.UNKNOWN: 1,
    HealthStatus.WARNING: 2,
    HealthStatus.ERROR: 3,
}


def _as_health_status(status: object) -> HealthStatus:
    """Coerce a driver's reported status (enum or string) to ``HealthStatus``.

    Unrecognised values map to ``UNKNOWN`` so a malformed report never passes
    as healthy.
    """
    if isinstance(status, HealthStatus):
        return status
    try:
        return HealthStatus(status)
    except ValueError:
        return HealthStatus.UNKNOWN


@dataclass(frozen=True)
class _BaseOrchestratorMeta(DriverMeta):
    id: str = "e7f3a1b2-orch-4000-9000-baseorch00001"
    name: str = "MCS Base Orchestrator"
    version: str = "0.1.0"
    bindings: tuple[DriverBinding, ...] = ()
    supported_llms: tuple[str, ...] = ("*",)
    capabilities: tuple[str, ...] = ("standalone", "orchestratable")


class BaseOrchestrator(BaseDriver, SupportsHealthcheck):
    """Generic multi-driver orchestrator with pluggable resolution strategy.

    Any ``MCSToolDriver`` can be registered via :meth:`add_driver`.
    Tool resolution (namespacing, switching, etc.) is handled by the
    ``ResolutionStrategy`` passed at construction time.

    The orchestrator is **composable**: because it implements
    ``MCSToolDriver`` (via ``BaseDriver``), it can itself be embedded
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
        self._resolution = resolution_strategy or ToolPipeline(
            layers=[NamespacingLayer()],
        )
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
            labeled_copy = dict(self._labeled)
        return self._resolution.execute_tool(labeled_copy, tool_name, arguments)

    # ------------------------------------------------------------------
    # Healthcheck (aggregate over first-level drivers)
    # ------------------------------------------------------------------

    def healthcheck(self) -> HealthCheckResult:
        """Aggregate health across the **first-level** registered drivers.

        For each registered driver that satisfies :class:`SupportsHealthcheck`
        (directly, or through a decorator that resolves it), the status is
        collected and the **worst** one wins -- so the result is ``OK`` only if
        *every* checkable driver is ``OK`` (a logical AND). A driver without the
        capability is skipped; if none support it there is nothing to check and
        the result is ``OK``.

        Nesting resolves itself: a registered driver that is *itself* a
        ``BaseOrchestrator`` provides ``healthcheck`` too, so calling it here
        cascades into that sub-orchestrator's own first level -- no recursive
        capability search required.

        Override in a subclass when "healthy" means something specific for your
        stack (only a primary counts, redundant drivers OR-aggregate, ...).
        """
        with self._lock:
            inners = list(self._labeled.values())
        worst = HealthStatus.OK
        for inner in inners:
            provider = DriverMeta.resolve_capability(inner, SupportsHealthcheck)
            if provider is None:
                continue
            status = _as_health_status(provider.healthcheck().get("status"))
            if _HEALTH_SEVERITY[status] > _HEALTH_SEVERITY[worst]:
                worst = status
        return {"status": worst}

    # ------------------------------------------------------------------
    # LLM integration (override to append layer instructions)
    # ------------------------------------------------------------------

    def get_driver_system_message(self, model_name: str | None = None) -> str:
        base_msg = super().get_driver_system_message(model_name)
        if isinstance(self._resolution, ToolPipeline):
            instructions = self._resolution.get_instructions()
            if instructions:
                base_msg += "\n\n" + instructions
        return base_msg
