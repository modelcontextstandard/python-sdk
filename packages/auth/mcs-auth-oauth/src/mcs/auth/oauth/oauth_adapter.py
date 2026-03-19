"""OAuth 2.0 Authorization Code Flow adapter for MCS.

Implements ``AuthPort`` using the standard Authorization Code Flow with
PKCE (RFC 7636).  Spins up a temporary local HTTP server to receive the
callback, opens the user's browser, exchanges the code for tokens, and
returns the result.

This adapter uses only the Python standard library -- no external
dependencies beyond ``mcs-auth``.
"""

from __future__ import annotations

import hashlib
import http.server
import json
import secrets
import urllib.parse
import urllib.request
import webbrowser
from base64 import urlsafe_b64encode
from typing import Any


class OAuthAdapter:
    """Auth transport adapter that performs OAuth 2.0 Authorization Code Flow.

    Satisfies ``AuthPort.authenticate(scope) -> str``.

    Parameters
    ----------
    authorize_url :
        Provider's authorization endpoint
        (e.g. ``"https://accounts.google.com/o/oauth2/v2/auth"``).
    token_url :
        Provider's token endpoint
        (e.g. ``"https://oauth2.googleapis.com/token"``).
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

        # Cache: scope → token dict
        self._tokens: dict[str, dict[str, Any]] = {}

    def authenticate(self, scope: str) -> str:
        """Run OAuth Authorization Code Flow and return the token.

        Returns the ``refresh_token`` if available, otherwise the
        ``access_token``.
        """
        if scope in self._tokens:
            tokens = self._tokens[scope]
            return tokens.get("refresh_token", tokens["access_token"])

        # Resolve OAuth scopes
        if isinstance(self._scopes, dict):
            oauth_scope = self._scopes.get(scope, "openid email offline_access")
        else:
            oauth_scope = self._scopes or "openid email offline_access"

        # PKCE (RFC 7636)
        code_verifier = secrets.token_urlsafe(64)
        code_challenge = urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).rstrip(b"=").decode()

        redirect_uri = f"http://localhost:{self._callback_port}{self._callback_path}"
        state = secrets.token_urlsafe(16)

        # Build authorization URL
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

        # Start callback server and open browser
        code = self._run_callback_server(auth_url, state)

        # Exchange code for tokens
        tokens = self._exchange_code(code, redirect_uri, code_verifier)
        self._tokens[scope] = tokens

        return tokens.get("refresh_token", tokens["access_token"])

    def _run_callback_server(self, auth_url: str, expected_state: str) -> str:
        """Open browser and wait for OAuth callback. Returns authorization code."""
        result: dict[str, str] = {}

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

            def log_message(self, *args: Any) -> None:
                pass  # suppress logs

        server = http.server.HTTPServer(
            ("localhost", self._callback_port), Handler
        )
        webbrowser.open(auth_url)
        server.handle_request()
        server.server_close()

        if "error" in result:
            raise RuntimeError(
                f"OAuth authorization failed: {result['error']} -- "
                f"{result.get('error_description', '')}"
            )
        if "code" not in result:
            raise RuntimeError("OAuth callback did not contain an authorization code.")
        if result.get("state") != expected_state:
            raise RuntimeError("OAuth state mismatch -- possible CSRF attack.")

        return result["code"]

    def _exchange_code(
        self, code: str, redirect_uri: str, code_verifier: str
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
