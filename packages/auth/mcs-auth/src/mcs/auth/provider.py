"""Credential provider abstraction for MCS.

Defines the contract that any credential provider must satisfy.
Providers **must** inherit from ``CredentialProvider`` and implement
``get_token``.  This is an ABC (not a Protocol) to enforce explicit
inheritance and make the contract unambiguous.

Optionally accepts a ``_token_cache`` implementing ``CachePort``
(from ``mcs-types-cache``) for persistent token storage across process
invocations.  When set, subclasses can use ``_cache_read`` /
``_cache_write`` / ``_cache_clear`` to persist credentials.  When
unset, all cache methods are silent no-ops.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class CredentialProvider(ABC):
    """Universal contract for retrieving credentials.

    A credential provider returns an access token (or API key) for a
    given *scope*.  Scopes are simple strings that identify what the
    token grants access to -- e.g. ``"gmail"``, ``"slack"``,
    ``"https://api.example.com"``.

    Implementations may fetch tokens from Auth0 Token Vault, a local
    keyring, environment variables, a static dict, or any other source.

    The provider is intentionally **synchronous**.  Async callers can
    wrap it in ``asyncio.to_thread``.

    Parameters
    ----------
    _token_cache :
        An object satisfying ``CachePort`` (``read`` / ``write`` /
        ``delete``).  ``None`` disables caching (the default).  The
        default file-based implementation is ``FileCacheStore`` from
        ``mcs-types-cache``.
    """

    def __init__(self, *, _token_cache: Any | None = None) -> None:
        self._token_cache = _token_cache

    # -- Cache helpers (no-ops when _token_cache is None) --------------------

    def _cache_read(self, key: str) -> str | None:
        """Return the cached value for *key*, or ``None`` on miss."""
        if self._token_cache is None:
            return None
        return self._token_cache.read(key)

    def _cache_write(
        self, key: str, value: str, *, ttl: float | None = None,
    ) -> None:
        """Persist *value* under *key*.  Optional *ttl* in seconds."""
        if self._token_cache is None:
            return
        if ttl is not None and hasattr(self._token_cache, "write"):
            # FileCacheStore.write() accepts ttl as keyword argument;
            # other CachePort implementations may not.
            try:
                self._token_cache.write(key, value, ttl=ttl)
            except TypeError:
                self._token_cache.write(key, value)
        else:
            self._token_cache.write(key, value)

    def _cache_clear(self, key: str) -> None:
        """Remove *key* from the persistent cache."""
        if self._token_cache is None:
            return
        self._token_cache.delete(key)

    # -- Token lifecycle ------------------------------------------------------

    def invalidate_token(self, scope: str) -> None:
        """Clear cached credentials for *scope*.

        Forces a fresh fetch on the next ``get_token`` call.  Subclasses
        should override to also clear in-memory caches.
        """
        self._cache_clear(f"at:{scope}")

    # -- Abstract API --------------------------------------------------------

    @abstractmethod
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
