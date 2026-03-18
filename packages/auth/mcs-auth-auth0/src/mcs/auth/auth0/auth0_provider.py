"""Auth0 Token Vault credential provider for MCS.

Implements ``CredentialProvider`` using two complementary RFCs:

1. **RFC 8628 -- Device Authorization Grant**: When no refresh token is
   available, the provider initiates an interactive device-authorisation
   flow.  An ``AuthChallenge`` is raised so the calling layer (typically
   ``AuthMixin``) can present the verification URL + user code to the
   end-user via the LLM.

2. **RFC 8693 -- OAuth 2.0 Token Exchange**: Once a refresh token is
   available, it is exchanged for an external provider's access token
   via Auth0's Token Vault (Connected Accounts).

No dependency on ``auth0-ai`` -- both flows are simple POSTs.
"""

from __future__ import annotations

import json
import logging
import time
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

# Device Authorization constants (RFC 8628)
_GRANT_TYPE_DEVICE_CODE = "urn:ietf:params:oauth:grant-type:device_code"

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

def _extract_response_body(err: Exception) -> str | None:
    """Try to extract the response body from an HTTP error.

    Works with ``requests.HTTPError`` (has ``err.response.text``) and
    ``urllib.error.HTTPError`` (has ``err.read()``).  Returns ``None``
    if the body cannot be extracted.
    """
    # requests.HTTPError
    resp = getattr(err, "response", None)
    if resp is not None:
        text = getattr(resp, "text", None)
        if text:
            return text

    # urllib.error.HTTPError
    read_fn = getattr(err, "read", None)
    if read_fn and callable(read_fn):
        try:
            return read_fn().decode()
        except Exception:
            pass

    return None


# Default OAuth scopes requested per connection during device auth
_DEFAULT_OAUTH_SCOPES: dict[str, str] = {
    "google-oauth2": (
        "openid email offline_access "
        "https://mail.google.com/ "
        "https://www.googleapis.com/auth/calendar "
        "https://www.googleapis.com/auth/drive"
    ),
    "slack": "openid email offline_access",
    "github": "openid email offline_access",
    "windowslive": "openid email offline_access",
}


class Auth0Provider:
    """Credential provider backed by Auth0 Token Vault with Device Flow.

    Parameters
    ----------
    domain :
        Auth0 tenant domain (e.g. ``"my-tenant.auth0.com"``).
    client_id :
        Auth0 application client ID.
    client_secret :
        Auth0 application client secret.
    refresh_token :
        Optional Auth0 refresh token.  When ``None``, the provider
        automatically initiates the Device Authorization Flow on the
        first ``get_token()`` call and raises ``AuthChallenge``.
    audience :
        Auth0 API audience for the device flow.  Defaults to
        ``https://<domain>/api/v2/``.
    connections :
        Optional mapping of MCS scope → Auth0 connection name.
        Merged with sensible defaults (``gmail`` → ``google-oauth2``, etc.).
    oauth_scopes :
        Optional mapping of Auth0 connection → OAuth scope string for
        the device-flow authorization request.
    poll_timeout :
        Maximum seconds to poll for device-flow completion (default 30).
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
        audience: str | None = None,
        connections: dict[str, str] | None = None,
        oauth_scopes: dict[str, str] | None = None,
        poll_timeout: int = 30,
        _http: Any | None = None,
    ) -> None:
        self._domain = domain.rstrip("/")
        self._client_id = client_id
        self._client_secret = client_secret
        self._refresh_token = refresh_token
        self._audience = audience or f"https://{self._domain}/api/v2/"
        self._poll_timeout = poll_timeout

        self._connections: dict[str, str] = {**_DEFAULT_CONNECTIONS}
        if connections:
            self._connections.update(connections)

        self._oauth_scopes: dict[str, str] = {**_DEFAULT_OAUTH_SCOPES}
        if oauth_scopes:
            self._oauth_scopes.update(oauth_scopes)

        if _http is not None:
            self._http = _http
        else:
            from mcs.adapter.http import HttpAdapter
            self._http = HttpAdapter()

        # Token cache: scope → (access_token, expires_at)
        self._cache: dict[str, tuple[str, float]] = {}

        # Device flow state (populated by _start_device_flow)
        self._device_code: str | None = None
        self._device_interval: int = 5
        self._verification_uri: str | None = None
        self._user_code: str | None = None

    # -- Public API ----------------------------------------------------------

    def get_token(self, scope: str) -> str:
        """Return a valid access token for *scope* via Auth0 Token Vault.

        If no refresh token is available, initiates the Device
        Authorization Flow and raises ``AuthChallenge`` so the caller
        can present the verification URL to the user.  On the next
        call (after the user has authenticated), the provider polls
        for completion and then performs the token exchange.

        Tokens are cached until 60 seconds before expiry.
        """
        # 1. Check cache
        if scope in self._cache:
            token, expires_at = self._cache[scope]
            if time.time() < expires_at:
                return token

        # 2. Have refresh token → token exchange (happy path)
        if self._refresh_token:
            return self._exchange_and_cache(scope)

        # 3. Have pending device code → poll for completion
        if self._device_code:
            try:
                self._poll_device_token()
            except AuthChallenge:
                raise
            except RuntimeError:
                # Terminal errors (access_denied, expired_token) → propagate
                raise
            except Exception:
                # HTTP-level error (403, network, etc.) → reset and start fresh
                logger.info("Device flow poll failed, restarting device flow")
                self._device_code = None

            if self._refresh_token:
                return self._exchange_and_cache(scope)

            if self._device_code:
                # User hasn't completed the flow yet
                raise AuthChallenge(
                    f"Authentication still pending for '{scope}'. "
                    f"Please open {self._verification_uri} and enter code: {self._user_code}",
                    url=self._verification_uri,
                    code=self._user_code,
                    scope=scope,
                )

        # 4. Nothing → start device flow
        self._start_device_flow(scope)
        raise AuthChallenge(
            f"Authentication required for '{scope}'. "
            f"Please open {self._verification_uri} and enter code: {self._user_code}",
            url=self._verification_uri,
            code=self._user_code,
            scope=scope,
        )

    # -- Device Authorization Flow (RFC 8628) --------------------------------

    def _start_device_flow(self, scope: str) -> None:
        """POST /oauth/device/code to initiate the device authorization flow."""
        url = f"https://{self._domain}/oauth/device/code"
        connection = self._resolve_connection(scope)
        oauth_scope = self._oauth_scopes.get(
            connection, "openid email offline_access"
        )

        body = {
            "client_id": self._client_id,
            "scope": oauth_scope,
            "audience": self._audience,
        }

        logger.info("Starting device authorization flow for scope=%s", scope)
        raw = self._http.request("POST", url, json_body=body)
        data = json.loads(raw)

        if "error" in data:
            raise RuntimeError(
                f"Auth0 device authorization failed: {data.get('error')} -- "
                f"{data.get('error_description', '')}"
            )

        self._device_code = data["device_code"]
        self._device_interval = data.get("interval", 5)
        self._verification_uri = data.get(
            "verification_uri_complete", data["verification_uri"]
        )
        self._user_code = data["user_code"]

        logger.info(
            "Device flow started: url=%s code=%s",
            self._verification_uri, self._user_code,
        )

    def _poll_device_token(self) -> None:
        """Poll /oauth/token until the user completes the device flow or timeout.

        Auth0 returns ``authorization_pending`` and ``slow_down`` as
        HTTP 403 responses, so the HTTP adapter will raise.  We catch
        that and parse the JSON body from the exception to handle the
        device-flow states correctly.
        """
        url = f"https://{self._domain}/oauth/token"
        deadline = time.time() + self._poll_timeout

        while time.time() < deadline:
            body = {
                "grant_type": _GRANT_TYPE_DEVICE_CODE,
                "device_code": self._device_code,
                "client_id": self._client_id,
            }

            try:
                raw = self._http.request("POST", url, json_body=body)
            except Exception as http_err:
                # Auth0 returns device-flow status as non-2xx (typically 403).
                # Try to extract the JSON body from the HTTP error.
                raw = _extract_response_body(http_err)
                if raw is None:
                    raise

            data = json.loads(raw)

            error = data.get("error")
            if error is None:
                # Success! We got tokens.
                self._refresh_token = data.get("refresh_token")
                self._device_code = None
                logger.info("Device flow completed successfully")
                return

            if error == "authorization_pending":
                time.sleep(self._device_interval)
                continue

            if error == "slow_down":
                self._device_interval += 5
                time.sleep(self._device_interval)
                continue

            if error == "expired_token":
                self._device_code = None
                raise RuntimeError(
                    "Device authorization expired. Please try again."
                )

            if error == "access_denied":
                self._device_code = None
                raise RuntimeError(
                    "Device authorization denied by user."
                )

            # Unknown error
            self._device_code = None
            raise RuntimeError(
                f"Auth0 device token poll failed: {error} -- "
                f"{data.get('error_description', '')}"
            )

        # Timeout reached -- user hasn't completed yet, keep device_code for retry
        logger.debug("Device flow poll timeout (%ds), will retry", self._poll_timeout)

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
