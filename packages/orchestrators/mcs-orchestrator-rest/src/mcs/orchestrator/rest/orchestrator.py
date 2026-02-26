"""MCS REST Orchestrator -- convenience orchestrator for OpenAPI endpoints.

Extends ``BaseOrchestrator`` with REST-specific methods to create
``HttpAdapter`` + ``RestToolDriver`` pairs from OpenAPI URLs.

All generic functionality (driver management, tool resolution,
prompt generation, LLM response parsing) is inherited.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from mcs.driver.core import DriverMeta, DriverBinding
from mcs.orchestrator.base import BaseOrchestrator, ResolutionStrategy

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class _RestOrchestratorMeta(DriverMeta):
    id: str = "e7f3a1b2-orch-4000-9000-restorch00001"
    name: str = "REST MCS Orchestrator"
    version: str = "0.3.0"
    bindings: tuple[DriverBinding, ...] = ()
    supported_llms: tuple[str, ...] = ("*",)
    capabilities: tuple[str, ...] = ("standalone", "orchestratable")


class RestOrchestrator(BaseOrchestrator):
    """Orchestrator for multiple REST/OpenAPI connections.

    Inherits all driver management, tool resolution, and LLM integration
    from ``BaseOrchestrator``.  Adds REST-specific convenience methods.
    """

    meta: DriverMeta = _RestOrchestratorMeta()

    def __init__(
        self,
        *,
        resolution_strategy: ResolutionStrategy | None = None,
    ) -> None:
        super().__init__(resolution_strategy=resolution_strategy)

    # ------------------------------------------------------------------
    # REST-specific convenience
    # ------------------------------------------------------------------

    def add_connection(
        self,
        url: str,
        *,
        label: str,
        **http_kwargs: Any,
    ) -> None:
        """Create an ``HttpAdapter`` + ``RestToolDriver`` and register them.

        Parameters
        ----------
        url :
            URL of the OpenAPI / Swagger specification.
        label :
            Human-readable identifier for this connection.
        **http_kwargs :
            Forwarded to ``HttpAdapter`` (e.g. ``proxy_url``,
            ``basic_user``, ``verify_ssl``, ``timeout``).
        """
        from mcs.adapter.http import HttpAdapter
        from mcs.driver.rest import RestToolDriver

        adapter = HttpAdapter(**http_kwargs)
        td = RestToolDriver(url, http=adapter)
        self.add_driver(td, label=label)

    def remove_connection(self, label: str) -> None:
        """Remove a previously added REST connection by *label*."""
        self.remove_driver(label)

    def list_connections(self) -> dict[str, DriverMeta]:
        """Return ``{label: DriverMeta}`` for every registered driver."""
        with self._lock:
            return {label: drv.meta for label, drv in self._labeled.items()}

    def _rebuild_meta(self) -> None:
        """Rebuild ``self.meta`` from the current set of drivers."""
        all_bindings = tuple(
            b for drv in self._labeled.values() for b in drv.meta.bindings
        )
        self.meta = DriverMeta(
            id=_RestOrchestratorMeta.id,
            name=_RestOrchestratorMeta.name,
            version=_RestOrchestratorMeta.version,
            bindings=all_bindings,
            supported_llms=("*",),
            capabilities=("standalone", "orchestratable"),
        )

    def add_driver(self, driver: Any, *, label: str) -> None:
        super().add_driver(driver, label=label)
        self._rebuild_meta()

    def remove_driver(self, label: str) -> Any:
        result = super().remove_driver(label)
        if result is not None:
            self._rebuild_meta()
        return result
