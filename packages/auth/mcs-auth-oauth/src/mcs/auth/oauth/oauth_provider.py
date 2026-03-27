"""OAuth credential provider for MCS.

A simple ``CredentialProvider`` that delegates to an ``AuthPort``
connector (defaults to ``OAuthConnector``).  For direct OAuth access
without a Token Vault intermediary (e.g. Google API directly).
"""

from __future__ import annotations

import time
from typing import Any


class OAuthProvider:
    """Credential provider using direct OAuth tokens.

    Wraps an ``AuthPort`` connector and caches the returned tokens.
    Use this when you want to use OAuth tokens directly (no Auth0
    Token Vault exchange).

    Parameters
    ----------
    _auth :
        Auth transport connector satisfying ``AuthPort``.  If not
        provided, you must supply ``OAuthConnector`` kwargs to build
        one automatically.
    **oauth_kwargs :
        Keyword arguments forwarded to ``OAuthConnector`` if ``_auth``
        is not provided.
    """

    def __init__(self, *, _auth: Any | None = None, **oauth_kwargs: Any) -> None:
        if _auth is not None:
            self._auth = _auth
        else:
            from .oauth_connector import OAuthConnector
            self._auth = OAuthConnector(**oauth_kwargs)

        # Cache: scope → (token, expires_at)
        self._cache: dict[str, tuple[str, float]] = {}

    def get_token(self, scope: str) -> str:
        """Return a valid token for *scope* via OAuth.

        Delegates to the ``AuthPort`` adapter and caches the result.
        """
        if scope in self._cache:
            token, expires_at = self._cache[scope]
            if time.time() < expires_at:
                return token

        token = self._auth.authenticate(scope)

        # Cache for 50 minutes (typical OAuth token lifetime is 1 hour)
        self._cache[scope] = (token, time.time() + 3000)

        return token
