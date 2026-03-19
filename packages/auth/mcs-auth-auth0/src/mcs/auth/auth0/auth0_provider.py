"""Auth0 Token Vault credential provider for MCS.

Implements ``CredentialProvider`` using RFC 8693 -- OAuth 2.0 Token
Exchange.  An Auth0 refresh token is exchanged for an external
provider's access token via Auth0's Token Vault (Connected Accounts).

The refresh token itself is obtained via an ``AuthPort`` adapter --
e.g. ``OAuthAdapter`` (Authorization Code Flow with local callback)
or ``LinkAuthAdapter`` (device-flow-like broker).  This keeps the
provider transport-agnostic: it doesn't know *how* the refresh token
was acquired, only that it can exchange it.

No dependency on ``auth0-ai`` -- the exchange is a simple POST.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Auth0 Token Exchange constants (RFC 8693)
# ---------------------------------------------------------------------------
_GRANT_TYPE_TOKEN_EXCHANGE = (
    "urn:auth0:params:oauth:grant-type:token-exchange:"
    "federated-connection-access-token"
)
_SUBJECT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:refresh_token"
_REQUESTED_TOKEN_TYPE = (
    "http://auth0.com/oauth/token-type/federated-connection-access-token"
)

# Default scope → Auth0 connection mapping
_DEFAULT_CONNECTIONS: dict[str, str] = {
    "gmail": "google-oauth2",
    "google": "google-oauth2",
    "google-calendar": "google-oauth2",
    "google-drive": "google-oauth2",
    "slack": "slack",
    "github": "github",
    "microsoft": "windowslive",
}


class Auth0Provider:
    """Credential provider backed by Auth0 Token Vault.

    Obtains an Auth0 refresh token from an ``AuthPort`` adapter and
    exchanges it for external provider access tokens via Token Vault.

    Parameters
    ----------
    domain :
        Auth0 tenant domain (e.g. ``"my-tenant.auth0.com"``).
    client_id :
        Auth0 application client ID.
    client_secret :
        Auth0 application client secret.
    refresh_token :
        Optional Auth0 refresh token.  If provided, the ``_auth``
        adapter is not used.
    connections :
        Optional mapping of MCS scope → Auth0 connection name.
        Merged with sensible defaults (``gmail`` → ``google-oauth2``, etc.).
    _auth :
        Auth transport adapter satisfying ``AuthPort``.  Used to obtain
        the Auth0 refresh token when ``refresh_token`` is not provided.
        Raises ``LookupError`` at ``get_token()`` time if neither
        ``refresh_token`` nor ``_auth`` is given.
    _http :
        HTTP transport satisfying ``request(method, url, *, json_body, headers) -> str``.
        Defaults to ``HttpAdapter`` from ``mcs-adapter-http``.
    """

    def __init__(
        self,
        *,
        domain: str,
        client_id: str,
        client_secret: str,
        refresh_token: str | None = None,
        connections: dict[str, str] | None = None,
        _auth: Any | None = None,
        _http: Any | None = None,
    ) -> None:
        self._domain = domain.rstrip("/")
        self._client_id = client_id
        self._client_secret = client_secret
        self._refresh_token = refresh_token
        self._auth = _auth

        self._connections: dict[str, str] = {**_DEFAULT_CONNECTIONS}
        if connections:
            self._connections.update(connections)

        if _http is not None:
            self._http = _http
        else:
            from mcs.adapter.http import HttpAdapter
            self._http = HttpAdapter()

        # Token cache: scope → (access_token, expires_at)
        self._cache: dict[str, tuple[str, float]] = {}

    # -- Public API ----------------------------------------------------------

    def get_token(self, scope: str) -> str:
        """Return a valid access token for *scope* via Auth0 Token Vault.

        1. Check cache
        2. If no refresh token, ask ``_auth`` adapter (may raise AuthChallenge)
        3. Exchange refresh token for external token via Token Vault

        Tokens are cached until 60 seconds before expiry.
        """
        # 1. Check cache
        if scope in self._cache:
            token, expires_at = self._cache[scope]
            if time.time() < expires_at:
                return token

        # 2. Obtain refresh token if needed
        if not self._refresh_token:
            if self._auth is None:
                raise LookupError(
                    f"No refresh token available for scope {scope!r} and no "
                    f"auth adapter configured.  Provide 'refresh_token' or '_auth'."
                )
            # AuthPort.authenticate may raise AuthChallenge
            self._refresh_token = self._auth.authenticate(scope)

        # 3. Token Vault exchange
        return self._exchange_and_cache(scope)

    # -- Token Exchange (RFC 8693) -------------------------------------------

    def _resolve_connection(self, scope: str) -> str:
        """Map an MCS scope to an Auth0 connection name."""
        if scope in self._connections:
            return self._connections[scope]
        # If the scope looks like a connection name already, pass it through
        if "-" in scope or scope.islower():
            return scope
        raise LookupError(
            f"No Auth0 connection mapped for scope {scope!r}.  "
            f"Known scopes: {sorted(self._connections.keys())}.  "
            f"Pass connections={{'{scope}': 'your-connection'}} to Auth0Provider."
        )

    def _exchange_token(self, connection: str) -> dict[str, Any]:
        """Perform the Auth0 token exchange (RFC 8693)."""
        url = f"https://{self._domain}/oauth/token"
        body = {
            "grant_type": _GRANT_TYPE_TOKEN_EXCHANGE,
            "subject_token": self._refresh_token,
            "subject_token_type": _SUBJECT_TOKEN_TYPE,
            "requested_token_type": _REQUESTED_TOKEN_TYPE,
            "connection": connection,
            "client_id": self._client_id,
            "client_secret": self._client_secret,
        }

        logger.debug("Token exchange for connection=%s", connection)
        raw = self._http.request("POST", url, json_body=body)
        data = json.loads(raw)

        if "error" in data:
            raise RuntimeError(
                f"Auth0 token exchange failed: {data.get('error')} -- "
                f"{data.get('error_description', '')}"
            )

        return data

    def _exchange_and_cache(self, scope: str) -> str:
        """Exchange + cache helper."""
        connection = self._resolve_connection(scope)
        data = self._exchange_token(connection)

        access_token = data["access_token"]
        expires_in = data.get("expires_in", 3600)
        self._cache[scope] = (access_token, time.time() + expires_in - 60)

        logger.info("Obtained token for scope=%s via connection=%s", scope, connection)
        return access_token
