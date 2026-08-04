"""AuthMiddleware -- turns an authentication challenge into an in-band result.

When ``execute_tool`` raises :class:`AuthChallenge` (because a ``CredentialProvider``
needs user interaction), this middleware catches it and returns a structured JSON result
instead of letting the exception propagate. The LLM then sees a *successful* tool call
whose content describes the authentication action the user must take.

This is the middleware successor to the former ``AuthMixin`` / ``AuthDecorator`` (ADR-0002).
Instead of wrapping the driver, it is added to the driver's middleware chain::

    driver = MailDriver(..., middleware=[AuthMiddleware()])
    # or later:  driver.add_middleware(AuthMiddleware())

Because the middleware sits around ``execute_tool`` *inside* the driver, the challenge is
caught before the driver's own ``try/except`` turns it into ``call_failed`` -- exactly the
effect the old ``AuthMixin`` achieved via MRO, now by composition. With no ``AuthMiddleware``
present the challenge simply degrades to ``call_failed`` (the graceful fallback).
"""

from __future__ import annotations

import json
from abc import ABC
from typing import Any

from mcs.driver.core import ToolMiddleware, CallNext

from .challenge import AuthChallenge


class SupportsAuth(ABC):
    """Marker contract: a layer that intercepts authentication challenges.

    Carries the ``"auth"`` capability flag, so a layer that offers this can be recognised
    with ``isinstance(obj, SupportsAuth)``. Note the flag is *not* folded onto the meta of
    a driver this middleware is added to: what a driver instance was configured with is
    runtime state, while ``DriverMeta`` stays a static description of the driver class.

    The contract ships **with this package**, not in core: any client that acts on auth is
    using ``mcs-auth`` anyway.
    """

    CAPABILITY = "auth"


class AuthMiddleware(ToolMiddleware, SupportsAuth):
    """Catches ``AuthChallenge`` from tool execution and converts it to a result."""

    def on_execute_tool(
        self, tool_name: str, arguments: dict[str, Any], call_next: CallNext,
    ) -> Any:
        try:
            return call_next(tool_name, arguments)
        except AuthChallenge as exc:
            payload: dict[str, Any] = {
                "auth_required": True,
                "message": str(exc),
            }
            if exc.url:
                payload["url"] = exc.url
            if exc.code:
                payload["code"] = exc.code
            if exc.scope:
                payload["scope"] = exc.scope
            return json.dumps(payload)
