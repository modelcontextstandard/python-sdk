"""LinkAuth credential provider for MCS.

A simple ``CredentialProvider`` that delegates to a ``LinkAuthConnector``
(or any ``AuthPort``).  For direct credential access via a LinkAuth
broker -- without a Token Vault intermediary.

Use ``Auth0Provider(... _auth=LinkAuthConnector(...))`` when you need
Auth0 Token Vault exchange on top.
"""

from __future__ import annotations

from typing import Any


class LinkAuthProvider:
    """Credential provider using a LinkAuth broker.

    Wraps an ``AuthPort`` connector (defaults to ``LinkAuthConnector``)
    and returns credentials directly.

    Parameters
    ----------
    _auth :
        Auth transport connector satisfying ``AuthPort``.  If not
        provided, ``LinkAuthConnector`` is created from ``**kwargs``.
    **kwargs :
        Keyword arguments forwarded to ``LinkAuthConnector`` if ``_auth``
        is not provided.
    """

    def __init__(self, *, _auth: Any | None = None, **kwargs: Any) -> None:
        if _auth is not None:
            self._auth = _auth
        else:
            from .linkauth_connector import LinkAuthConnector
            self._auth = LinkAuthConnector(**kwargs)

    def get_token(self, scope: str) -> str:
        """Return a credential for *scope* via LinkAuth broker."""
        return self._auth.authenticate(scope)
