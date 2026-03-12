"""Credential provider abstraction for MCS.

Defines the contract that any credential provider must satisfy.
Providers fulfil this protocol through structural subtyping -- they do
**not** need to import or inherit from this module.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class CredentialProvider(Protocol):
    """Universal contract for retrieving credentials.

    A credential provider returns an access token (or API key) for a
    given *scope*.  Scopes are simple strings that identify what the
    token grants access to -- e.g. ``"gmail"``, ``"slack"``,
    ``"https://api.example.com"``.

    Implementations may fetch tokens from Auth0 Token Vault, a local
    keyring, environment variables, a static dict, or any other source.

    The provider is intentionally **synchronous**.  Async callers can
    wrap it in ``asyncio.to_thread``.
    """

    def get_token(self, scope: str) -> str:
        """Return a valid access token / API key for *scope*.

        Implementations should handle caching and refresh internally
        so that callers always receive a usable token.

        Raises
        ------
        LookupError
            When no credential is available for the requested scope.
        RuntimeError
            When the underlying auth flow fails (network, config, ...).
        """
        ...
