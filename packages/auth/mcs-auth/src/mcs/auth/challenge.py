"""Authentication challenge -- raised when credentials are not yet available.

This exception is part of the lazy-auth pattern: a
``CredentialProvider`` raises ``AuthChallenge`` when it cannot supply a
token *yet* but has started an interactive flow (e.g. device
authorisation) that the end-user must complete first.

The ``AuthMixin`` (see ``mcs.auth.mixin``) catches this exception at
the ``execute_tool`` boundary and converts it into a structured tool
result that the LLM can present to the user.
"""

from __future__ import annotations


class AuthChallenge(Exception):
    """Raised when credentials require user interaction before they become available.

    Parameters
    ----------
    message :
        Human-readable description of what the user needs to do.
    url :
        Verification URL the user should open (e.g. device-flow URI).
    code :
        User code to enter at *url* (device-flow pattern).
    scope :
        The scope that triggered the challenge (e.g. ``"gmail"``).
    """

    def __init__(
        self,
        message: str,
        *,
        url: str | None = None,
        code: str | None = None,
        scope: str | None = None,
    ) -> None:
        self.url = url
        self.code = code
        self.scope = scope
        super().__init__(message)
