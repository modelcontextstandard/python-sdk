"""PermissionMiddleware -- asks for consent before executing a tool call.

Before continuing the chain to ``execute_tool``, it calls a consent handler with the
pending tool name and arguments. If consent is denied, the call is **not** executed and a
structured result is returned instead (a short-circuit -- ``call_next`` is not called).

This is the middleware successor to ``PermissionDecorator`` (ADR-0002). Added to a driver's
middleware chain rather than wrapping it::

    driver = MailDriver(..., middleware=[PermissionMiddleware(consent_handler=ask_user)])

The handler may be supplied at construction (``consent_handler=...``) or registered /
replaced later via :meth:`SupportsConsent.set_consent_handler` -- useful when the UI that
answers consent only becomes available at runtime. ``ask_user(tool_name, arguments) -> bool``
returns whether the call is allowed. One ``PermissionMiddleware`` instance can be shared
across every driver in a client (it holds only the handler, no per-call state).
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any, Callable

from mcs.driver.core import ToolMiddleware, CallNext

#: A callback that decides whether a pending tool call may run.
ConsentCallback = Callable[[str, "dict[str, Any]"], bool]


class SupportsConsent(ABC):
    """Contract: this layer gates tool execution behind user consent.

    Carries the ``"consent"`` capability flag (so a layer that offers this is recognisable
    with ``isinstance``) and exposes :meth:`set_consent_handler`. The client keeps its own
    reference to the middleware to (re)register the handler at runtime -- no lookup
    needed, because the client constructed it. The flag is *not* folded onto the driver's
    meta: ``DriverMeta`` stays a static description of the driver class, and which
    middleware an instance runs is runtime configuration.

    The contract ships **with this package**, not in core.
    """

    CAPABILITY = "consent"

    @abstractmethod
    def set_consent_handler(self, consent_handler: ConsentCallback) -> None:
        """Register or replace the consent handler at runtime."""
        ...


class PermissionMiddleware(ToolMiddleware, SupportsConsent):
    """Gates ``execute_tool`` behind a consent handler.

    The handler may be passed at construction (``consent_handler=...``) or set later via
    :meth:`set_consent_handler`.
    """

    def __init__(self, *, consent_handler: ConsentCallback | None = None) -> None:
        self._consent_handler = consent_handler

    def set_consent_handler(self, consent_handler: ConsentCallback) -> None:
        self._consent_handler = consent_handler

    def on_execute_tool(
        self, tool_name: str, arguments: dict[str, Any], call_next: CallNext,
    ) -> Any:
        if self._consent_handler is None:
            raise RuntimeError(
                "PermissionMiddleware has no consent handler -- pass consent_handler=... at "
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
        return call_next(tool_name, arguments)
