"""Auth0 Token Vault credential provider for MCS.

Implements ``CredentialProvider`` using RFC 8693 -- OAuth 2.0 Token
Exchange.  An Auth0 refresh token is exchanged for an external
provider's access token via Auth0's Token Vault (Connected Accounts).

The refresh token itself is obtained via an ``AuthPort`` adapter --
e.g. ``OAuthAdapter`` (Authorization Code Flow with local callback)
or ``LinkAuthAdapter`` (device-flow-like broker).  This keeps the
provider transport-agnostic: it doesn't know *how* the refresh token
was acquired, only that it can exchange it.

When Token Vault has no Connected Account for the user yet, the
provider automatically runs the Connected Accounts setup flow
(MRRT exchange, ``POST /connect``, browser consent,
``POST /complete``).  This is a one-time action per user per
connection.  The flow is non-blocking: an ``AuthChallenge`` is
raised so the caller can inform the user about the browser
interaction.

No dependency on ``auth0-ai`` -- all exchanges are simple POSTs.
"""

from __future__ import annotations

import hashlib
import http.server
import json
import logging
import secrets
import threading
import time
import urllib.parse
import urllib.request
import webbrowser
from base64 import urlsafe_b64encode
from typing import Any

from mcs.auth.challenge import AuthChallenge

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

_NOT_FOUND_ERROR = "federated_connection_refresh_token_not_found"

# Default scope -> Auth0 connection mapping
_DEFAULT_CONNECTIONS: dict[str, str] = {
    "gmail": "google-oauth2",
    "google": "google-oauth2",
    "google-calendar": "google-oauth2",
    "google-drive": "google-oauth2",
    "slack": "slack",
    "github": "github",
    "microsoft": "windowslive",
}

# Scopes required for the My Account API Connected Accounts management
_MA_SCOPES = (
    "openid profile offline_access "
    "create:me:connected_accounts "
    "read:me:connected_accounts "
    "delete:me:connected_accounts"
)


# ---------------------------------------------------------------------------
# _PendingConnect -- background callback for Connected Accounts flow
# ---------------------------------------------------------------------------

class _PendingConnect:
    """Tracks an in-flight Connected Accounts consent flow.

    Starts a one-shot callback server in a daemon thread and opens
    the browser to the ``connect_uri``.  The caller polls
    ``is_ready`` / ``is_waiting`` and retrieves the connect code
    via ``get_code``.
    """

    def __init__(
        self,
        *,
        port: int,
        path: str,
        expected_state: str,
        code_verifier: str,
        redirect_uri: str,
        auth_session: str,
    ) -> None:
        self._port = port
        self._expected_state = expected_state
        self.code_verifier = code_verifier
        self.redirect_uri = redirect_uri
        self.auth_session = auth_session

        self._result: dict[str, str] = {}
        self._thread: threading.Thread | None = None
        self._server: http.server.HTTPServer | None = None

    def start(self, browser_url: str) -> None:
        result = self._result

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                params = urllib.parse.parse_qs(
                    urllib.parse.urlparse(self.path).query,
                )
                if "connect_code" in params:
                    result["code"] = params["connect_code"][0]
                if "code" in params:
                    result.setdefault("code", params["code"][0])
                if "state" in params:
                    result["state"] = params["state"][0]
                if "error" in params:
                    result["error"] = params["error"][0]
                    result["error_description"] = params.get(
                        "error_description", [""],
                    )[0]
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<h1>OK! You can close this window.</h1>")

            def log_message(self, *_a: Any) -> None:
                pass

        self._server = http.server.HTTPServer(("localhost", self._port), Handler)

        def _serve() -> None:
            assert self._server is not None
            self._server.handle_request()
            self._server.server_close()

        self._thread = threading.Thread(target=_serve, daemon=True)
        self._thread.start()
        webbrowser.open(browser_url)

    def is_ready(self) -> bool:
        return "code" in self._result or "error" in self._result

    def is_waiting(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def get_code(self) -> str:
        if "error" in self._result:
            raise RuntimeError(
                f"Connected Accounts authorization failed: "
                f"{self._result['error']} -- "
                f"{self._result.get('error_description', '')}"
            )
        if "code" not in self._result:
            raise RuntimeError(
                "Connected Accounts callback did not contain a connect_code."
            )
        return self._result["code"]


# ---------------------------------------------------------------------------
# Auth0Provider
# ---------------------------------------------------------------------------

class Auth0Provider:
    """Credential provider backed by Auth0 Token Vault.

    Obtains an Auth0 refresh token from an ``AuthPort`` adapter and
    exchanges it for external provider access tokens via Token Vault.

    When Token Vault returns ``federated_connection_refresh_token_not_found``
    the provider automatically initiates the Connected Accounts setup
    flow.  This is non-blocking: an ``AuthChallenge`` is raised so the
    caller can inform the user about the required browser interaction.
    On the next call the provider completes the flow and retries the
    Token Vault exchange.

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
        Optional mapping of MCS scope -> Auth0 connection name.
        Merged with sensible defaults (``gmail`` -> ``google-oauth2``).
    connection_scopes :
        Optional mapping of MCS scope -> list of external OAuth scopes
        to request when setting up a Connected Account
        (e.g. ``{"gmail": ["https://mail.google.com/", "openid"]}``).
        Required for automatic Connected Accounts setup.
    callback_port :
        Local port for the Connected Accounts callback (default 3000).
    callback_path :
        Path on the local server for the callback (default ``"/callback"``).
    _auth :
        Auth transport adapter satisfying ``AuthPort``.  Used to obtain
        the Auth0 refresh token when ``refresh_token`` is not provided.
    _http :
        HTTP transport satisfying
        ``request(method, url, *, json_body, headers) -> str``.
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
        connection_scopes: dict[str, list[str]] | None = None,
        callback_port: int = 3000,
        callback_path: str = "/callback",
        _auth: Any | None = None,
        _http: Any | None = None,
    ) -> None:
        self._domain = domain.rstrip("/")
        self._client_id = client_id
        self._client_secret = client_secret
        self._refresh_token = refresh_token
        self._auth = _auth
        self._callback_port = callback_port
        self._callback_path = callback_path

        self._connections: dict[str, str] = {**_DEFAULT_CONNECTIONS}
        if connections:
            self._connections.update(connections)

        self._connection_scopes: dict[str, list[str]] = connection_scopes or {}

        if _http is not None:
            self._http = _http
        else:
            from mcs.adapter.http import HttpAdapter
            self._http = HttpAdapter()

        # Token cache: scope -> (access_token, expires_at)
        self._cache: dict[str, tuple[str, float]] = {}
        # Pending Connected Accounts flow (at most one at a time)
        self._ca_pending: _PendingConnect | None = None
        # My Account API token (cached for the duration of a setup flow)
        self._ma_token: str | None = None

    # -- Public API ----------------------------------------------------------

    def get_token(self, scope: str) -> str:
        """Return a valid access token for *scope* via Auth0 Token Vault.

        1. Check cache.
        2. If no refresh token, ask ``_auth`` adapter (may raise
           ``AuthChallenge``).
        3. Exchange refresh token for external token via Token Vault.
           If Token Vault has no Connected Account, initiate the
           Connected Accounts setup (may raise ``AuthChallenge``).

        Tokens are cached until 60 s before expiry.
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

        # 3. Token Vault exchange (with automatic Connected Accounts setup)
        return self._exchange_and_cache(scope)

    # -- Token Exchange (RFC 8693) -------------------------------------------

    def _resolve_connection(self, scope: str) -> str:
        """Map an MCS scope to an Auth0 connection name."""
        if scope in self._connections:
            return self._connections[scope]
        if "-" in scope or scope.islower():
            return scope
        raise LookupError(
            f"No Auth0 connection mapped for scope {scope!r}.  "
            f"Known scopes: {sorted(self._connections.keys())}.  "
            f"Pass connections={{'{scope}': 'your-connection'}} to Auth0Provider."
        )

    def _post_token_endpoint(self, body: dict[str, Any]) -> dict[str, Any]:
        """POST to ``/oauth/token`` and return parsed JSON.

        Always returns a dict -- the caller checks for ``"error"``.
        """
        url = f"https://{self._domain}/oauth/token"
        resp = self._http.request("POST", url, json_body=body)
        try:
            data = resp.json()
        except (ValueError, KeyError):
            data = {}
        if not resp.ok and "error" not in data:
            data["error"] = f"http_{resp.status_code}"
            data.setdefault("error_description", resp.text)
        return data

    def _exchange_token(self, connection: str) -> dict[str, Any]:
        """Perform the Auth0 token exchange (RFC 8693)."""
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
        data = self._post_token_endpoint(body)

        if "error" in data:
            raise RuntimeError(
                f"Auth0 token exchange failed: {data.get('error')} -- "
                f"{data.get('error_description', '')}"
            )

        return data

    def _exchange_and_cache(self, scope: str) -> str:
        """Exchange + cache, with Connected Accounts auto-setup on failure."""
        connection = self._resolve_connection(scope)

        try:
            data = self._exchange_token(connection)
        except RuntimeError as exc:
            if _NOT_FOUND_ERROR not in str(exc):
                raise
            # Token Vault has no Connected Account -> set one up
            logger.info(
                "No Connected Account for connection=%s -- "
                "initiating setup flow",
                connection,
            )
            self._ensure_connected_account(connection, scope)
            # If _ensure_connected_account returns (instead of raising
            # AuthChallenge), the setup is complete -- retry exchange.
            data = self._exchange_token(connection)

        access_token = data["access_token"]
        expires_in = data.get("expires_in", 3600)
        self._cache[scope] = (access_token, time.time() + expires_in - 60)

        logger.info(
            "Obtained token for scope=%s via connection=%s", scope, connection,
        )
        return access_token

    # -- Connected Accounts setup --------------------------------------------

    def _ensure_connected_account(
        self, connection: str, scope: str,
    ) -> None:
        """State machine for the Connected Accounts setup flow.

        - **No pending flow**: MRRT exchange, ``POST /connect``, start
          background callback server, open browser, raise
          ``AuthChallenge``.
        - **Pending, callback received**: ``POST /complete``, clear
          state, return (caller retries Token Vault exchange).
        - **Pending, still waiting**: raise ``AuthChallenge``.
        """
        # Pending flow -- callback arrived?
        if self._ca_pending is not None:
            pending = self._ca_pending
            if pending.is_ready():
                self._complete_connect_flow(pending)
                self._ca_pending = None
                self._ma_token = None
                return

            raise AuthChallenge(
                "Waiting for Token Vault authorization -- please "
                "complete the consent in your browser.",
                scope=scope,
            )

        # No flow started -- kick one off
        if scope not in self._connection_scopes:
            raise RuntimeError(
                f"Auth0 Token Vault has no Connected Account for "
                f"connection {connection!r} and no connection_scopes "
                f"configured for scope {scope!r}.  Provide "
                f"connection_scopes={{'{scope}': [...]}} to "
                f"Auth0Provider so the Connected Account can be "
                f"created automatically."
            )

        self._start_connect_flow(connection, scope)
        # _start_connect_flow always raises AuthChallenge

    def _mrrt_exchange(self) -> str:
        """Exchange Auth0 refresh_token for a My Account API access_token."""
        if self._ma_token:
            return self._ma_token

        body = {
            "grant_type": "refresh_token",
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "refresh_token": self._refresh_token,
            "audience": f"https://{self._domain}/me/",
            "scope": _MA_SCOPES,
        }

        data = self._post_token_endpoint(body)
        if "error" in data:
            raise RuntimeError(
                f"MRRT exchange failed: {data.get('error')} -- "
                f"{data.get('error_description', '')}"
            )

        self._ma_token = data["access_token"]
        logger.debug("MRRT exchange succeeded -- obtained My Account API token")
        return self._ma_token

    def _start_connect_flow(self, connection: str, scope: str) -> None:
        """POST /connect, start background callback server, raise AuthChallenge."""
        ma_token = self._mrrt_exchange()

        redirect_uri = (
            f"http://localhost:{self._callback_port}{self._callback_path}"
        )
        state = secrets.token_urlsafe(16)
        code_verifier = secrets.token_urlsafe(64)
        code_challenge = urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).rstrip(b"=").decode()

        connect_url = (
            f"https://{self._domain}/me/v1/connected-accounts/connect"
        )
        connect_body = {
            "connection": connection,
            "redirect_uri": redirect_uri,
            "state": state,
            "scopes": self._connection_scopes[scope],
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "authorization_params": {"prompt": "consent"},
        }

        raw = self._post_json_bearer(connect_url, connect_body, ma_token)
        data = json.loads(raw)
        if "error" in data or "connect_uri" not in data:
            raise RuntimeError(
                f"Connected Accounts /connect failed: "
                f"{data.get('error', data)}"
            )

        connect_uri = data["connect_uri"]
        ticket = data["connect_params"]["ticket"]
        auth_session = data["auth_session"]

        pending = _PendingConnect(
            port=self._callback_port,
            path=self._callback_path,
            expected_state=state,
            code_verifier=code_verifier,
            redirect_uri=redirect_uri,
            auth_session=auth_session,
        )
        browser_url = f"{connect_uri}?ticket={ticket}"
        pending.start(browser_url)
        self._ca_pending = pending

        logger.info(
            "Connected Accounts setup started for connection=%s -- "
            "browser opened for consent",
            connection,
        )
        raise AuthChallenge(
            "One-time setup: a browser window has been opened to "
            "authorize Token Vault access for your account. "
            "Please complete the consent and try again.",
            scope=scope,
        )

    def _complete_connect_flow(self, pending: _PendingConnect) -> None:
        """POST /complete with the connect_code from the callback."""
        ma_token = self._mrrt_exchange()
        connect_code = pending.get_code()

        complete_url = (
            f"https://{self._domain}/me/v1/connected-accounts/complete"
        )
        complete_body = {
            "auth_session": pending.auth_session,
            "connect_code": connect_code,
            "redirect_uri": pending.redirect_uri,
            "code_verifier": pending.code_verifier,
        }

        raw = self._post_json_bearer(complete_url, complete_body, ma_token)
        data = json.loads(raw)
        if "error" in data:
            raise RuntimeError(
                f"Connected Accounts /complete failed: "
                f"{data.get('error', data)}"
            )

        logger.info(
            "Connected Account created: id=%s connection=%s",
            data.get("id", "?"),
            data.get("connection", "?"),
        )

    # -- HTTP helpers --------------------------------------------------------

    def _post_json_bearer(
        self, url: str, body: dict[str, Any], bearer: str,
    ) -> str:
        """POST JSON with Bearer token, return raw response body."""
        data = json.dumps(body).encode()
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {bearer}",
            },
        )
        try:
            resp = urllib.request.urlopen(req)
            return resp.read().decode()
        except urllib.error.HTTPError as exc:
            return exc.read().decode()
