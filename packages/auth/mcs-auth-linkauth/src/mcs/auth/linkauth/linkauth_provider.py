"""LinkAuth credential provider for MCS.

A simple ``CredentialProvider`` that delegates to a ``LinkAuthConnector``
(or any ``AuthPort``).  For direct credential access via a LinkAuth
broker -- without a Token Vault intermediary.

Use ``Auth0Provider(... _auth=LinkAuthConnector(...))`` when you need
Auth0 Token Vault exchange on top.
"""

from __future__ import annotations

import logging
from typing import Any

from mcs.auth.provider import CredentialProvider

logger = logging.getLogger(__name__)


class LinkAuthProvider(CredentialProvider):
    """Credential provider using a LinkAuth broker.

    Wraps an ``AuthPort`` connector (defaults to ``LinkAuthConnector``)
    and returns credentials directly.

    Parameters
    ----------
    _auth :
        Auth transport connector satisfying ``AuthPort``.  If not
        provided, ``LinkAuthConnector`` is created from ``**kwargs``.
    _token_cache :
        ``CachePort`` implementation for persisting tokens across
        process invocations.  ``None`` disables persistent caching.
    **kwargs :
        Keyword arguments forwarded to ``LinkAuthConnector`` if ``_auth``
        is not provided.
    """

    def __init__(
        self,
        *,
        _auth: Any | None = None,
        _token_cache: Any | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(_token_cache=_token_cache)

        if _auth is not None:
            self._auth = _auth
        else:
            from .linkauth_connector import LinkAuthConnector
            self._auth = LinkAuthConnector(_token_cache=_token_cache, **kwargs)

    def get_token(self, scope: str) -> str:
        """Return a credential for *scope* via LinkAuth broker."""
        cached = self._cache_read(f"linkauth:{scope}")
        if cached is not None:
            logger.debug("Restored token from cache for scope=%s", scope)
            return cached

        token = self._auth.authenticate(scope)
        self._cache_write(f"linkauth:{scope}", token)
        return token
