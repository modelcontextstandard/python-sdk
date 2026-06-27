"""AuthDecorator -- intercepts authentication challenges at the ToolDriver boundary.

Wraps an ``MCSToolDriver`` (via :class:`BaseDecorator`). When ``execute_tool``
raises :class:`AuthChallenge` (because a ``CredentialProvider`` needs user
interaction), the decorator catches it and returns a structured JSON result
instead of letting the exception propagate. The LLM then sees a *successful*
tool call whose content describes the authentication action the user must take.

This is the composition-based successor to the former ``AuthMixin``. Instead of
mixing it into a driver via inheritance::

    class MyDriver(AuthMixin, BaseDriver): ...        # old

wrap the tool driver and compose it like any other driver::

    auth = AuthDecorator(MyToolDriver(...))            # new
    orchestrator.add_driver(auth, label="mail")

Because the decorator wraps the **ToolDriver** layer (``execute_tool``), the
surrounding driver or orchestrator keeps its single ``process_llm_response``
loop and calls ``execute_tool`` -- the decorator -- beneath it.
"""

from __future__ import annotations

import json
from abc import ABC
from typing import Any

from mcs.driver.core import BaseDecorator

from .challenge import AuthChallenge


class SupportsAuth(ABC):
    """Marker contract: this layer intercepts authentication challenges.

    Carries the ``"auth"`` capability flag, so the feature is detectable through
    ``meta.capabilities`` and the intercepting layer is reachable via
    ``DriverMeta.resolve_capability(driver, SupportsAuth)`` -- no matter how deep
    it sits in a decorator/orchestrator stack.

    The contract ships **with this package**, not in core: any client that wants
    to act on auth is using ``mcs-auth`` anyway, and a generic client detects the
    capability via the ``"auth"`` flag in ``meta.capabilities`` without it.
    """

    CAPABILITY = "auth"


class AuthDecorator(BaseDecorator, SupportsAuth):
    """Catches ``AuthChallenge`` from tool execution and converts it to a result.

    Overrides only ``execute_tool``; everything else (``list_tools``,
    capability aggregation, resolution) is delegated by :class:`BaseDecorator`.
    """

    CONTRACT = SupportsAuth

    def execute_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        try:
            return self._inner.execute_tool(tool_name, arguments)
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
