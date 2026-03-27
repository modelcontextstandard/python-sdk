"""Authentication port abstractions for MCS.

Defines the contract that any auth transport connector must satisfy.
Connectors fulfil this protocol through structural subtyping -- they do
**not** need to import or inherit from this module.

This follows the same pattern as ``MailboxPort`` and ``HttpPort``:
the driver/provider depends on the protocol, not on a concrete connector.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class AuthPort(Protocol):
    """Transport abstraction for obtaining authentication tokens.

    An ``AuthPort`` connector handles the actual mechanism for acquiring
    a token -- OAuth Authorization Code Flow, LinkAuth device-flow
    broker, environment variables, or any other source.

    The provider (e.g. ``Auth0Provider``) calls ``authenticate`` to get
    the raw token, then applies any additional steps (like Token Vault
    exchange) on top.

    Implementations **may** raise ``AuthChallenge`` when user interaction
    is required (e.g. opening a URL, entering a code).

    **Passthrough mode** (optional *url* / *callback_params* / *state*):

    When *url* is provided the connector performs a custom redirect flow
    instead of its default OAuth / credential flow:

    1. Redirect the user's browser to *url*.
    2. Capture the query parameters listed in *callback_params* from
       the resulting callback.
    3. Return the first captured parameter value as a string.

    *state* is an opaque value for CSRF protection and callback
    correlation on shared callback endpoints.
    """

    def authenticate(
        self,
        scope: str,
        *,
        url: str | None = None,
        callback_params: list[str] | None = None,
        state: str | None = None,
    ) -> str:
        """Return a raw token (or captured callback parameter) for *scope*.

        Parameters
        ----------
        scope :
            Identifier for the requested credential (e.g. ``"gmail"``,
            ``"slack"``, ``"openai"``).
        url :
            Custom authorization URL for passthrough redirects.  When
            set, the connector redirects the user here instead of
            constructing its own authorize URL.
        callback_params :
            Query-parameter names to extract from the callback in
            passthrough mode (e.g. ``["connect_code"]``).
        state :
            Opaque state for CSRF protection / callback correlation.

        Returns
        -------
        str
            The token string, or the first captured callback parameter
            when in passthrough mode.

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
