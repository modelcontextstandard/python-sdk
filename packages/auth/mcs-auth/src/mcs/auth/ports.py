"""Authentication port abstractions for MCS.

Defines the contract that any auth transport adapter must satisfy.
Adapters fulfil this protocol through structural subtyping -- they do
**not** need to import or inherit from this module.

This follows the same pattern as ``MailboxPort`` and ``HttpPort``:
the driver/provider depends on the protocol, not on a concrete adapter.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class AuthPort(Protocol):
    """Transport abstraction for obtaining authentication tokens.

    An ``AuthPort`` adapter handles the actual mechanism for acquiring a
    token -- OAuth Authorization Code Flow, LinkAuth device-flow broker,
    environment variables, or any other source.

    The provider (e.g. ``Auth0Provider``) calls ``authenticate`` to get
    the raw token, then applies any additional steps (like Token Vault
    exchange) on top.

    Implementations **may** raise ``AuthChallenge`` when user interaction
    is required (e.g. opening a URL, entering a code).
    """

    def authenticate(self, scope: str) -> str:
        """Return a raw token (e.g. refresh token, access token, API key) for *scope*.

        Parameters
        ----------
        scope :
            Identifier for the requested credential (e.g. ``"gmail"``,
            ``"slack"``, ``"openai"``).

        Returns
        -------
        str
            The token string.

        Raises
        ------
        AuthChallenge
            When user interaction is needed before the token can be
            obtained.
        LookupError
            When no credential is available and no interactive flow
            can be started.
        RuntimeError
            When the auth flow fails (network, config, etc.).
        """
        ...
