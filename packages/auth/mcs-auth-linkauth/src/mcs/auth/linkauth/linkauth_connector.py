"""LinkAuth credential broker connector for MCS.

This is a *Connector*, not a Transport Adapter: it translates between
the LinkAuth broker REST API and the ``AuthPort`` contract.  The real
transport is HTTP, handled by the injected ``_http`` backend (default:
``HttpAdapter`` from ``mcs-adapter-http``).

Implements ``AuthPort`` using the LinkAuth device-flow-like pattern:

1. Agent creates a session at the broker (with public key)
2. Raises ``AuthChallenge`` so the LLM shows the URL + code to the user
3. User opens URL, enters credentials or completes OAuth
4. Agent polls the broker for completion
5. Broker returns encrypted credentials
6. Agent decrypts with its private key

Zero-knowledge: the broker never sees credentials in plaintext (for
form-based flows).  OAuth flows have a documented caveat where the
broker briefly handles tokens server-side before encrypting.
"""

from __future__ import annotations

import base64
import json
import logging
import time
from typing import Any, Protocol, runtime_checkable

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from mcs.adapter.http import HttpResponse
from mcs.auth.challenge import AuthChallenge

logger = logging.getLogger(__name__)


@runtime_checkable
class HttpPort(Protocol):
    """Contract for HTTP transport (same pattern as GmailConnector)."""

    def request(
        self,
        method: str,
        url: str,
        *,
        json_body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        timeout: int | None = None,
    ) -> HttpResponse: ...


class LinkAuthConnector:
    """LinkAuth broker connector for MCS auth flows.

    Satisfies ``AuthPort.authenticate(scope) -> str``.

    Parameters
    ----------
    broker_url :
        Base URL of the LinkAuth broker (e.g. ``"https://auth.example.com"``).
    template :
        LinkAuth template ID (e.g. ``"google_mail"``, ``"api_key"``,
        ``"openai"``).  Can be a dict mapping MCS scopes to template IDs.
    display_name :
        Human-readable name shown to the user (e.g. ``"Gmail Access"``).
    poll_interval :
        Seconds between poll requests (default 5).
    poll_timeout :
        Max seconds to poll before giving up (default 0 = don't block,
        raise AuthChallenge immediately for retry).
    token_field :
        Field name in the decrypted credentials to return as the token.
        For OAuth templates this is typically ``"refresh_token"`` or
        ``"access_token"``.  For form templates it's the field name
        (e.g. ``"api_key"``).  Default: auto-detect.
    _token_cache :
        ``CachePort`` implementation for persisting session state and
        RSA keys across process invocations.  Required for short-lived
        processes (CLI skills) where ``AuthChallenge`` causes the
        process to exit before the user completes authentication.
    """

    def __init__(
        self,
        *,
        broker_url: str,
        template: dict[str, str] | str = "api_key",
        display_name: str | None = None,
        oauth_provider: str | None = None,
        oauth_scopes: list[str] | None = None,
        oauth_extra_params: dict[str, str] | None = None,
        api_key: str | None = None,
        poll_interval: int = 5,
        poll_timeout: int = 0,
        token_field: str | None = None,
        _http: HttpPort | None = None,
        _token_cache: Any | None = None,
    ) -> None:
        self._broker_url = broker_url.rstrip("/")
        self._template = template
        self._display_name = display_name
        self._oauth_provider = oauth_provider
        self._oauth_scopes = oauth_scopes
        self._oauth_extra_params = oauth_extra_params
        self._api_key = api_key
        self._poll_interval = poll_interval
        self._poll_timeout = poll_timeout
        self._token_field = token_field
        self._cache = _token_cache

        if _http is not None:
            self._http: HttpPort = _http
        else:
            from mcs.adapter.http import HttpAdapter
            self._http = HttpAdapter()

        # RSA keypair -- restore from cache or generate fresh
        cached_pem = self._cache.read("linkauth:privkey") if self._cache else None
        if cached_pem is not None:
            self._private_key = serialization.load_pem_private_key(
                cached_pem.encode(), password=None,
            )
            logger.debug("Restored RSA key from cache")
        else:
            self._private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            if self._cache is not None:
                pem = self._private_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                ).decode()
                self._cache.write("linkauth:privkey", pem)

        self._public_key_b64 = base64.b64encode(
            self._private_key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).decode()

        # Session state per scope -- restore from cache
        self._sessions: dict[str, _SessionState] = {}
        cached_sessions = self._cache.read("linkauth:sessions") if self._cache else None
        if cached_sessions is not None:
            for key, s in json.loads(cached_sessions).items():
                self._sessions[key] = _SessionState(**s)
            logger.debug("Restored %d session(s) from cache", len(self._sessions))

        # Cached tokens -- restore from cache
        self._tokens: dict[str, str] = {}
        cached_tokens = self._cache.read("linkauth:tokens") if self._cache else None
        if cached_tokens is not None:
            self._tokens = json.loads(cached_tokens)
            logger.debug("Restored %d token(s) from cache", len(self._tokens))

    @property
    def callback_url(self) -> str:
        """Broker's OAuth callback URL (usable as redirect_uri)."""
        return f"{self._broker_url}/v1/oauth/callback"

    def proxy_http(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        json_body: dict[str, Any] | None = None,
        timeout: int = 30,
    ) -> dict[str, Any]:
        """Make an HTTP request through the broker's proxy endpoint.

        Returns the parsed response as a dict with ``status_code``,
        ``headers``, and ``body`` (raw string).  Raises ``RuntimeError``
        on broker-level failures (proxy disabled, connection error, etc.).
        """
        proxy_url = f"{self._broker_url}/v1/proxy"
        payload: dict[str, Any] = {
            "method": method,
            "url": url,
            "timeout": timeout,
        }
        if headers:
            payload["headers"] = headers
        if json_body is not None:
            payload["body"] = json.dumps(json_body)

        req_headers: dict[str, str] = {}
        if self._api_key:
            req_headers["X-API-Key"] = self._api_key

        resp = self._http.request(
            "POST", proxy_url, json_body=payload, headers=req_headers,
        )
        if not resp.ok:
            raise RuntimeError(
                f"Broker proxy returned {resp.status_code}: {resp.text}"
            )
        return resp.json()

    def authenticate(
        self,
        scope: str,
        *,
        url: str | None = None,
        callback_params: list[str] | None = None,
        state: str | None = None,
    ) -> str:
        """Create a LinkAuth session and return the credential.

        **Default mode** (``url`` is *None*):
        On first call, creates a session and raises ``AuthChallenge``
        with the URL for the user.  On subsequent calls, polls the
        broker.  When ready, decrypts and returns the token.

        **Passthrough mode** (``url`` is set):
        Creates a session with a custom authorize URL.  The broker
        redirects the user there and captures the callback parameters
        specified in *callback_params*.  Returns the first captured
        value.
        """
        # Passthrough mode uses state as correlation key.  The second
        # call (polling) may omit url while keeping the same state, so
        # we key on state presence rather than url presence.
        cache_key = f"{scope}:redirect:{state}" if (url is not None or state is not None) else scope

        # Already have a token for this key
        if cache_key in self._tokens:
            return self._tokens[cache_key]

        # Existing session -> poll
        if cache_key in self._sessions:
            session = self._sessions[cache_key]
            token = self._poll_session(session, cache_key)
            if token is not None:
                self._tokens[cache_key] = token
                del self._sessions[cache_key]
                self._persist_state()
                return token
            raise AuthChallenge(
                f"Authentication pending for '{scope}'. "
                f"Please open {session.url} and enter code: {session.code}",
                url=session.url,
                code=session.code,
                scope=scope,
            )

        # New session
        session = self._create_session(
            scope,
            custom_authorize_url=url,
            custom_callback_params=callback_params,
            custom_state=state,
        )
        self._sessions[cache_key] = session
        self._persist_state()

        # Try immediate poll if timeout > 0
        if self._poll_timeout > 0:
            token = self._poll_session(session, cache_key)
            if token is not None:
                self._tokens[cache_key] = token
                del self._sessions[cache_key]
                self._persist_state()
                return token

        raise AuthChallenge(
            f"Authentication required for '{scope}'. "
            f"Please open {session.url} and enter code: {session.code}",
            url=session.url,
            code=session.code,
            scope=scope,
        )

    # -- Cache persistence ---------------------------------------------------

    def _persist_state(self) -> None:
        """Write sessions and tokens to the persistent cache."""
        if self._cache is None:
            return
        sessions_dict = {
            k: s.to_dict() for k, s in self._sessions.items()
        }
        self._cache.write("linkauth:sessions", json.dumps(sessions_dict))
        self._cache.write("linkauth:tokens", json.dumps(self._tokens))

    # -- Internal helpers ----------------------------------------------------

    def _resolve_template(self, scope: str) -> str:
        if isinstance(self._template, dict):
            return self._template.get(scope, "api_key")
        return self._template

    def _create_session(
        self,
        scope: str,
        *,
        custom_authorize_url: str | None = None,
        custom_callback_params: list[str] | None = None,
        custom_state: str | None = None,
    ) -> _SessionState:
        """POST /v1/sessions to create a new LinkAuth session."""
        url = f"{self._broker_url}/v1/sessions"
        payload: dict[str, Any] = {
            "public_key": self._public_key_b64,
            "template": self._resolve_template(scope),
            "display_name": self._display_name or f"Access for {scope}",
        }
        if self._oauth_provider:
            payload["oauth_provider"] = self._oauth_provider
        if self._oauth_scopes:
            payload["oauth_scopes"] = self._oauth_scopes
        if self._oauth_extra_params:
            payload["oauth_extra_params"] = self._oauth_extra_params
        if custom_authorize_url:
            payload["custom_authorize_url"] = custom_authorize_url
        if custom_callback_params:
            payload["custom_callback_params"] = custom_callback_params
        if custom_state:
            payload["custom_state"] = custom_state

        headers: dict[str, str] = {}
        if self._api_key:
            headers["X-API-Key"] = self._api_key

        resp = self._http.request("POST", url, json_body=payload, headers=headers)
        if not resp.ok:
            logger.error(
                "LinkAuth session creation failed: %s — %s",
                resp.status_code, resp.text,
            )
            raise RuntimeError(
                f"LinkAuth broker returned {resp.status_code}: {resp.text}"
            )
        data = resp.json()

        logger.info(
            "LinkAuth session created: url=%s code=%s",
            data["url"], data["code"],
        )

        return _SessionState(
            session_id=data["session_id"],
            code=data["code"],
            url=data["url"],
            poll_token=data["poll_token"],
            interval=data.get("interval", self._poll_interval),
        )

    def _poll_session(self, session: _SessionState, scope: str) -> str | None:
        """Poll the broker for session completion. Returns token or None."""
        url = f"{self._broker_url}/v1/sessions/{session.session_id}"
        deadline = time.time() + self._poll_timeout

        while True:
            poll_headers: dict[str, str] = {
                "Authorization": f"Bearer {session.poll_token}",
            }
            if self._api_key:
                poll_headers["X-API-Key"] = self._api_key

            resp = self._http.request("GET", url, headers=poll_headers)

            if resp.status_code == 429:
                try:
                    err_data = resp.json()
                    if err_data.get("type", "").endswith("slow_down"):
                        session.interval = err_data.get(
                            "interval", session.interval + 5
                        )
                except (ValueError, KeyError):
                    pass
                if time.time() >= deadline:
                    return None
                time.sleep(session.interval)
                continue

            if not resp.ok:
                if time.time() >= deadline:
                    return None
                time.sleep(session.interval)
                continue

            data = resp.json()
            status = data.get("status")

            if status == "ready":
                ciphertext = data.get("ciphertext", "")
                algorithm = data.get("algorithm", "")
                return self._decrypt(ciphertext, algorithm, scope)

            if status in ("consumed", "expired"):
                raise RuntimeError(
                    f"LinkAuth session {status} for scope '{scope}'"
                )

            if time.time() >= deadline:
                return None
            time.sleep(session.interval)

    def _decrypt(self, ciphertext_b64: str, algorithm: str, scope: str) -> str:
        """Decrypt the credential payload from LinkAuth."""
        outer = json.loads(base64.b64decode(ciphertext_b64))

        wrapped_key = base64.b64decode(outer["wrapped_key"])
        iv = base64.b64decode(outer["iv"])
        ct = base64.b64decode(outer["ciphertext"])

        # Unwrap AES key with RSA-OAEP
        aes_key = self._private_key.decrypt(
            wrapped_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # Decrypt with AES-GCM
        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(iv, ct, None)
        credentials = json.loads(plaintext)

        logger.info("Decrypted credentials for scope=%s", scope)

        # Extract the token from the credentials dict
        return self._extract_token(credentials, scope)

    def _extract_token(self, credentials: dict[str, Any], scope: str) -> str:
        """Extract the relevant token from decrypted credentials."""
        # Explicit field override
        if self._token_field and self._token_field in credentials:
            return str(credentials[self._token_field])

        # OAuth tokens: prefer refresh_token, then access_token
        if "refresh_token" in credentials:
            return credentials["refresh_token"]
        if "access_token" in credentials:
            return credentials["access_token"]

        # Form fields: try api_key, password, token, secret
        for field in ("api_key", "password", "token", "secret", "key"):
            if field in credentials:
                return str(credentials[field])

        # Single field → return its value
        if len(credentials) == 1:
            return str(next(iter(credentials.values())))

        raise LookupError(
            f"Cannot determine which field to use as token for scope '{scope}'. "
            f"Available fields: {sorted(credentials.keys())}. "
            f"Set token_field= in LinkAuthConnector."
        )


class _SessionState:
    """Internal state for a pending LinkAuth session."""

    __slots__ = ("session_id", "code", "url", "poll_token", "interval")

    def __init__(
        self,
        session_id: str,
        code: str,
        url: str,
        poll_token: str,
        interval: int,
    ) -> None:
        self.session_id = session_id
        self.code = code
        self.url = url
        self.poll_token = poll_token
        self.interval = interval

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "code": self.code,
            "url": self.url,
            "poll_token": self.poll_token,
            "interval": self.interval,
        }
