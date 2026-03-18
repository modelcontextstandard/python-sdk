"""AuthMixin -- intercepts authentication challenges at the tool-execution boundary.

This mixin is designed to be mixed into any ``DriverBase`` subclass.
When a tool execution raises ``AuthChallenge`` (because a
``CredentialProvider`` needs user interaction), the mixin catches the
exception and returns a structured JSON result instead of letting
``DriverBase`` treat it as a generic failure.

The LLM sees the result as a *successful* tool call whose content
describes the authentication action the user must take.  This keeps
auth concerns completely outside of ``DriverBase`` (core).

Usage::

    from mcs.auth.mixin import AuthMixin
    from mcs.driver.core import DriverBase

    class MyDriver(AuthMixin, DriverBase):
        ...

Python's MRO ensures ``AuthMixin.execute_tool`` wraps
``DriverBase.execute_tool`` (via ``super()``).
"""

from __future__ import annotations

import json
from typing import Any

from .challenge import AuthChallenge


class AuthMixin:
    """Catches ``AuthChallenge`` from tool execution and converts it to a tool result.

    The mixin overrides ``execute_tool`` so that ``DriverBase.process_llm_response``
    receives a normal result string (not an exception), allowing the LLM to present
    the authentication instructions to the user naturally.
    """

    def execute_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        try:
            return super().execute_tool(tool_name, arguments)  # type: ignore[misc]
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
