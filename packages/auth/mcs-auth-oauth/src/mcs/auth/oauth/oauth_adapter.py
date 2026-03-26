"""OAuth 2.0 Authorization Code Flow adapter for MCS.

Implements ``AuthPort`` using the standard Authorization Code Flow with
PKCE (RFC 7636).  Opens the user's browser and starts a background
callback server so that ``authenticate()`` returns immediately with an
``AuthChallenge`` instead of blocking.  On the next call the adapter
checks whether the callback has arrived and, if so, exchanges the code
for tokens.

This adapter uses only the Python standard library -- no external
dependencies beyond ``mcs-auth``.
"""

from __future__ import annotations

import hashlib
import http.server
import json
import logging
import secrets
import threading
import urllib.parse
import urllib.request
import webbrowser
from base64 import urlsafe_b64encode
from typing import Any

from mcs.auth.challenge import AuthChallenge

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# _PendingAuth -- background callback server + state
# ---------------------------------------------------------------------------

class _PendingAuth:
    """Tracks a single in-flight OAuth Authorization Code Flow.

    Starts a one-shot HTTP server in a daemon thread and opens the
    browser.  The caller polls ``is_ready`` / ``is_waiting`` and
    retrieves the authorization code via ``get_code`` once the
    callback has arrived.
    """

    def __init__(
        self,
        *,
        port: int,
        path: str,
        expected_state: str,
        code_verifier: str,
        redirect_uri: str,
    ) -> None:
        self._port = port
        self._path = path
        self._expected_state = expected_state
        self.code_verifier = code_verifier
        self.redirect_uri = redirect_uri

        self._result: dict[str, str] = {}
        self._thread: threading.Thread | None = None
        self._server: http.server.HTTPServer | None = None

    # -- lifecycle -----------------------------------------------------------

    def start(self, auth_url: str) -> None:
        """Create the callback server, open the browser, return immediately."""
        result = self._result

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                params = urllib.parse.parse_qs(
                    urllib.parse.urlparse(self.path).query
                )
                if "code" in params:
                    result["code"] = params["code"][0]
                    result["state"] = params.get("state", [""])[0]
                if "error" in params:
                    result["error"] = params["error"][0]
                    result["error_description"] = params.get(
                        "error_description", [""]
                    )[0]
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(
                    b"<h1>OK! You can close this window.</h1>"
                )

            def log_message(self, *_a: Any) -> None:
                pass

        self._server = http.server.HTTPServer(("localhost", self._port), Handler)

        def _serve() -> None:
            assert self._server is not None
            self._server.handle_request()
            self._server.server_close()

        self._thread = threading.Thread(target=_serve, daemon=True)
        self._thread.start()
        webbrowser.open(auth_url)

    # -- query ---------------------------------------------------------------

    def is_ready(self) -> bool:
        return "code" in self._result or "error" in self._result

    def is_waiting(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def get_code(self) -> str:
        """Return the authorization code or raise on error/state mismatch."""
        if "error" in self._result:
            raise RuntimeError(
                f"OAuth authorization failed: {self._result['error']} -- "
                f"{self._result.get('error_description', '')}"
            )
        if "code" not in self._result:
            raise RuntimeError("OAuth callback did not contain an authorization code.")
        if self._result.get("state") != self._expected_state:
            raise RuntimeError("OAuth state mismatch -- possible CSRF attack.")
        return self._result["code"]


# ---------------------------------------------------------------------------
# OAuthAdapter
# ---------------------------------------------------------------------------

class OAuthAdapter:
    """Non-blocking auth transport using OAuth 2.0 Authorization Code Flow.

    Satisfies ``AuthPort.authenticate(scope) -> str``.

    On the **first** call for a given scope the adapter opens a browser,
    starts a background callback server, and raises ``AuthChallenge`` so
    the caller (usually ``AuthMixin``) can inform the user.  On the
    **next** call the adapter checks whether the callback arrived and,
    if so, exchanges the code for tokens.  If the user has not yet
    logged in, another ``AuthChallenge`` is raised.

    Parameters
    ----------
    authorize_url :
        Provider's authorization endpoint.
    token_url :
        Provider's token endpoint.
    client_id :
        OAuth client ID.
    client_secret :
        OAuth client secret (empty string for public clients with PKCE).
    scopes :
        OAuth scopes to request.  Can be a dict mapping MCS scope names
        to OAuth scope strings, or a single string applied to all scopes.
    callback_port :
        Local port for the redirect callback (default 3000).
    callback_path :
        Path on the local server for the callback (default ``"/callback"``).
    extra_params :
        Extra query params to include in the authorization URL
        (e.g. ``{"connection": "google-oauth2"}`` for Auth0).
    """

    def __init__(
        self,
        *,
        authorize_url: str,
        token_url: str,
        client_id: str,
        client_secret: str = "",
        scopes: dict[str, str] | str = "",
        callback_port: int = 3000,
        callback_path: str = "/callback",
        extra_params: dict[str, str] | None = None,
    ) -> None:
        self._authorize_url = authorize_url
        self._token_url = token_url
        self._client_id = client_id
        self._client_secret = client_secret
        self._scopes = scopes
        self._callback_port = callback_port
        self._callback_path = callback_path
        self._extra_params = extra_params or {}

        self._tokens: dict[str, dict[str, Any]] = {}
        self._pending: dict[str, _PendingAuth] = {}

    # -- public API ----------------------------------------------------------

    def authenticate(self, scope: str) -> str:
        """Return a token for *scope*, or raise ``AuthChallenge``.

        The method implements a three-state machine per scope:

        1. **Tokens cached** -- return immediately.
        2. **Pending flow, callback received** -- exchange code, cache
           tokens, return.
        3. **Pending flow, still waiting** -- raise ``AuthChallenge``.
        4. **No flow started** -- start background server, open browser,
           raise ``AuthChallenge``.

        Returns the ``refresh_token`` if available, otherwise the
        ``access_token``.
        """
        # 1. Already have tokens
        if scope in self._tokens:
            tokens = self._tokens[scope]
            return tokens.get("refresh_token", tokens["access_token"])

        # 2. Pending flow -- callback arrived?
        if scope in self._pending:
            pending = self._pending[scope]
            if pending.is_ready():
                code = pending.get_code()
                tokens = self._exchange_code(
                    code, pending.redirect_uri, pending.code_verifier,
                )
                self._tokens[scope] = tokens
                del self._pending[scope]
                logger.info("OAuth flow completed for scope=%s", scope)
                return tokens.get("refresh_token", tokens["access_token"])

            # 3. Still waiting
            raise AuthChallenge(
                "Waiting for login -- please complete the sign-in in your browser.",
                scope=scope,
            )

        # 4. Start a new flow
        oauth_scope = self._resolve_scopes(scope)

        code_verifier = secrets.token_urlsafe(64)
        code_challenge = urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).rstrip(b"=").decode()

        redirect_uri = (
            f"http://localhost:{self._callback_port}{self._callback_path}"
        )
        state = secrets.token_urlsafe(16)

        params: dict[str, str] = {
            "response_type": "code",
            "client_id": self._client_id,
            "redirect_uri": redirect_uri,
            "scope": oauth_scope,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            **self._extra_params,
        }
        auth_url = f"{self._authorize_url}?{urllib.parse.urlencode(params)}"

        pending = _PendingAuth(
            port=self._callback_port,
            path=self._callback_path,
            expected_state=state,
            code_verifier=code_verifier,
            redirect_uri=redirect_uri,
        )
        pending.start(auth_url)
        self._pending[scope] = pending

        logger.info("OAuth flow started for scope=%s -- browser opened", scope)
        raise AuthChallenge(
            "A browser window has been opened for you to sign in. "
            "Please complete the login and try again.",
            scope=scope,
        )

    # -- internal ------------------------------------------------------------

    def _resolve_scopes(self, scope: str) -> str:
        if isinstance(self._scopes, dict):
            return self._scopes.get(scope, "openid email offline_access")
        return self._scopes or "openid email offline_access"

    def _exchange_code(
        self, code: str, redirect_uri: str, code_verifier: str,
    ) -> dict[str, Any]:
        """Exchange authorization code for tokens."""
        body = json.dumps({
            "grant_type": "authorization_code",
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
        }).encode()
        req = urllib.request.Request(
            self._token_url,
            data=body,
            headers={"Content-Type": "application/json"},
        )
        try:
            resp = urllib.request.urlopen(req)
            return json.loads(resp.read())
        except Exception as exc:
            read_fn = getattr(exc, "read", None)
            detail = read_fn().decode() if read_fn and callable(read_fn) else str(exc)
            raise RuntimeError(f"OAuth token exchange failed: {detail}") from exc
