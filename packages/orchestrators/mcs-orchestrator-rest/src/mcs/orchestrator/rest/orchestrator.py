"""MCS REST Orchestrator -- dynamic multi-connection orchestrator.

Manages multiple ``MCSToolDriver`` instances at runtime, each identified
by a human-readable *label*.  Provides convenience methods for REST/OpenAPI
connections (``add_connection`` / ``remove_connection``) that internally
create ``HttpAdapter`` + ``RestToolDriver`` pairs.

Inherits prompt generation and LLM response parsing from ``DriverBase``.
Uses ``UnknownToolBehavior.RETRY_WITH_LIST`` so the LLM gets feedback
when it calls a tool that does not exist.

**Namespacing:** When more than one driver is registered, tool names are
automatically prefixed as ``{label}__{original_name}`` so the LLM can
distinguish between tools from different connections.  When only a single
driver is registered the prefix is omitted for cleaner prompts.

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
    JsonPromptStrategy,
    UnknownToolBehavior,
)

logger = logging.getLogger(__name__)

NAMESPACE_SEP = "__"


@dataclass(frozen=True)
class _OrchestratorMeta(DriverMeta):
    id: str = "e7f3a1b2-orch-4000-9000-restorch00001"
    name: str = "REST MCS Orchestrator"
    version: str = "0.3.0"
    bindings: tuple[DriverBinding, ...] = ()
    supported_llms: tuple[str, ...] = ("*",)
    capabilities: tuple[str, ...] = ("standalone", "orchestratable")


class RestOrchestrator(DriverBase):
    """Dynamic orchestrator for multiple REST/OpenAPI connections.

    Any ``MCSToolDriver`` can be registered via :meth:`add_driver`.
    For REST/OpenAPI endpoints the convenience method :meth:`add_connection`
    creates the ``HttpAdapter`` and ``RestToolDriver`` automatically.

    The orchestrator is **composable**: because it implements
    ``MCSToolDriver`` (via ``DriverBase``), it can itself be embedded
    in another orchestrator.
    """

    meta: DriverMeta = _OrchestratorMeta()

    def __init__(self) -> None:
        strategy = JsonPromptStrategy.from_defaults()
        strategy.unknown_tool_behavior = UnknownToolBehavior.RETRY_WITH_LIST
        super().__init__(prompt_strategy=strategy)
        self._labeled: dict[str, MCSToolDriver] = {}
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Dynamic driver management
    # ------------------------------------------------------------------

    def add_driver(self, driver: MCSToolDriver, *, label: str) -> None:
        """Register a ``MCSToolDriver`` under *label*.

        Raises ``ValueError`` if *label* is already in use or contains
        the namespace separator.
        """
        if NAMESPACE_SEP in label:
            raise ValueError(
                f"Label must not contain '{NAMESPACE_SEP}': {label!r}"
            )
        with self._lock:
            if label in self._labeled:
                raise ValueError(f"Label already in use: {label!r}")
            self._labeled[label] = driver
            self._rebuild_meta()
        logger.info("Driver registered: label=%s, name=%s", label, driver.meta.name)

    def remove_driver(self, label: str) -> MCSToolDriver | None:
        """Unregister and return the driver stored under *label*.

        Returns ``None`` if the label was not found.
        """
        with self._lock:
            driver = self._labeled.pop(label, None)
            if driver is not None:
                self._rebuild_meta()
                logger.info("Driver removed: label=%s", label)
            return driver

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

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _rebuild_meta(self) -> None:
        """Rebuild ``self.meta`` from the current set of drivers."""
        all_bindings = tuple(
            b for drv in self._labeled.values() for b in drv.meta.bindings
        )
        self.meta = DriverMeta(
            id=_OrchestratorMeta.id,
            name=_OrchestratorMeta.name,
            version=_OrchestratorMeta.version,
            bindings=all_bindings,
            supported_llms=("*",),
            capabilities=("standalone", "orchestratable"),
        )

    def _use_namespace(self) -> bool:
        """Return ``True`` when tool-name namespacing is active."""
        return len(self._labeled) > 1

    def _namespaced_name(self, label: str, tool_name: str) -> str:
        if self._use_namespace():
            return f"{label}{NAMESPACE_SEP}{tool_name}"
        return tool_name

    def _resolve_tool(self, tool_name: str) -> tuple[MCSToolDriver, str]:
        """Map a (possibly namespaced) *tool_name* to ``(driver, original_name)``.

        Raises ``ValueError`` when no matching driver is found.
        """
        if self._use_namespace() and NAMESPACE_SEP in tool_name:
            label, original = tool_name.split(NAMESPACE_SEP, 1)
            driver = self._labeled.get(label)
            if driver is not None:
                return driver, original

        for drv in self._labeled.values():
            if any(t.name == tool_name for t in drv.list_tools()):
                return drv, tool_name

        raise ValueError(f"No tool '{tool_name}' found across registered drivers.")

    # ------------------------------------------------------------------
    # MCSToolDriver (orchestratable / composable)
    # ------------------------------------------------------------------

    def list_tools(self) -> list[Tool]:
        with self._lock:
            tools: list[Tool] = []
            for label, driver in self._labeled.items():
                for tool in driver.list_tools():
                    ns_name = self._namespaced_name(label, tool.name)
                    if self._use_namespace():
                        desc = f"[{label}] {tool.description}"
                    else:
                        desc = tool.description
                    tools.append(Tool(
                        name=ns_name,
                        description=desc,
                        parameters=list(tool.parameters),
                    ))
            return tools

    def execute_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        with self._lock:
            driver, original_name = self._resolve_tool(tool_name)
        return driver.execute_tool(original_name, arguments)

    # ------------------------------------------------------------------
    # Override: inject connection info into system message
    # ------------------------------------------------------------------

    def get_driver_system_message(self, model_name: str | None = None) -> str:
        base_msg = super().get_driver_system_message(model_name)
        connections = self.list_connections()
        if len(connections) <= 1:
            return base_msg

        labels = ", ".join(connections.keys())
        connection_info = (
            f"You have access to {len(connections)} connection(s): {labels}.\n"
            "Tool names are prefixed with the connection label "
            f"(e.g. label{NAMESPACE_SEP}tool_name) when multiple connections "
            "are active.\n\n"
        )
        return connection_info + base_msg
