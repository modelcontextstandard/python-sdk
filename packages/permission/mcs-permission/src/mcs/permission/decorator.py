"""PermissionDecorator -- asks for consent before executing a tool call.

Wraps an ``MCSToolDriver`` (via :class:`BaseDecorator`). Before delegating
``execute_tool``, it calls a consent handler with the pending tool name and
arguments. If consent is denied, the call is **not** executed and a structured
result is returned instead.

This realises the consent seam described in the MCS security model: the
ToolDriver layer is a natural point between *parse* and *execute* where a client
can confirm or deny a tool call. Composed like any other driver::

    perm = PermissionDecorator(MyToolDriver(...), consent=ask_user)
    orchestrator.add_driver(perm, label="mail")

The handler may be supplied at construction (``consent=...``) or registered /
replaced later via :meth:`SupportsConsent.set_consent` -- useful when the UI that
answers consent only becomes available at runtime. ``ask_user(tool_name,
arguments) -> bool`` returns whether the call is allowed. Decorators stack, so
``Permission(Auth(RealToolDriver))`` checks consent first and handles auth
challenges beneath it.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any, Callable

from mcs.driver.core import BaseDecorator, MCSToolDriver

#: A callback that decides whether a pending tool call may run.
ConsentCallback = Callable[[str, "dict[str, Any]"], bool]


class SupportsConsent(ABC):
    """Contract: this layer gates tool execution behind user consent.

    Carries the ``"consent"`` capability flag (detectable via
    ``meta.capabilities``) and exposes :meth:`set_consent`, so a client that
    resolves the layer -- ``DriverMeta.resolve_capability(driver,
    SupportsConsent)`` -- can register or replace the consent handler at runtime.

    The contract ships **with this package**, not in core: any client that acts
    on consent is using ``mcs-permission`` anyway, and a generic client detects
    the capability via the ``"consent"`` flag without it.
    """

    CAPABILITY = "consent"

    @abstractmethod
    def set_consent_handler(self, consent_handler: ConsentCallback) -> None:
        """Register or replace the consent handler at runtime."""
        ...


class PermissionDecorator(BaseDecorator, SupportsConsent):
    """Gates ``execute_tool`` behind a consent handler.

    The handler may be passed at construction (``consent=...``) or set later via
    :meth:`set_consent_handler`. Overrides only ``execute_tool``; ``list_tools``,
    capability aggregation and resolution are delegated by :class:`BaseDecorator`.
    """

    CONTRACT = SupportsConsent

    def __init__(
        self, inner: MCSToolDriver, *, consent_handler: ConsentCallback | None = None
    ) -> None:
        super().__init__(inner)
        self._consent_handler = consent_handler

    def set_consent_handler(self, consent_handler: ConsentCallback) -> None:
        self._consent_handler = consent_handler

    def execute_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        if self._consent_handler is None:
            raise RuntimeError(
                "PermissionDecorator has no consent handler -- pass consent_handler=... at "
                "construction or call set_consent_handler(...) before executing tools."
            )
        if not self._consent_handler(tool_name, arguments):
            return json.dumps(
                {
                    "permission_denied": True,
                    "tool": tool_name,
                    "message": f"User denied execution of {tool_name!r}.",
                }
            )
        return self._inner.execute_tool(tool_name, arguments)
