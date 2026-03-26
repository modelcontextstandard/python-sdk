"""LinkAuth credential broker adapter for MCS.

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
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, cast

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from mcs.auth.challenge import AuthChallenge

logger = logging.getLogger(__name__)


class LinkAuthAdapter:
    """Auth transport adapter that uses a LinkAuth broker.

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

        # RSA keypair (generated once per adapter instance)
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self._public_key_b64 = base64.b64encode(
            self._private_key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).decode()

        # Session state per scope
        self._sessions: dict[str, _SessionState] = {}
        # Cached tokens
        self._tokens: dict[str, str] = {}

    def authenticate(self, scope: str) -> str:
        """Create a LinkAuth session and return the credential.

        On first call, creates a session and raises ``AuthChallenge``
        with the URL for the user.  On subsequent calls, polls the
        broker.  When ready, decrypts and returns the token.
        """
        # Already have a token for this scope
        if scope in self._tokens:
            return self._tokens[scope]

        # Existing session → poll
        if scope in self._sessions:
            session = self._sessions[scope]
            token = self._poll_session(session, scope)
            if token is not None:
                self._tokens[scope] = token
                del self._sessions[scope]
                return token
            # Still pending → raise challenge
            raise AuthChallenge(
                f"Authentication pending for '{scope}'. "
                f"Please open {session.url} and enter code: {session.code}",
                url=session.url,
                code=session.code,
                scope=scope,
            )

        # New session
        session = self._create_session(scope)
        self._sessions[scope] = session

        # Try immediate poll if timeout > 0
        if self._poll_timeout > 0:
            token = self._poll_session(session, scope)
            if token is not None:
                self._tokens[scope] = token
                del self._sessions[scope]
                return token

        raise AuthChallenge(
            f"Authentication required for '{scope}'. "
            f"Please open {session.url} and enter code: {session.code}",
            url=session.url,
            code=session.code,
            scope=scope,
        )

    # -- Internal helpers ----------------------------------------------------

    def _resolve_template(self, scope: str) -> str:
        if isinstance(self._template, dict):
            return self._template.get(scope, "api_key")
        return self._template

    def _create_session(self, scope: str) -> _SessionState:
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
        body = json.dumps(payload).encode()

        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._api_key:
            headers["X-API-Key"] = self._api_key
        req = urllib.request.Request(url, data=body, headers=headers)
        try:
            resp = urllib.request.urlopen(req)
        except urllib.error.HTTPError as exc:
            err_body = ""
            try:
                err_body = exc.read().decode()
            except Exception:
                pass
            logger.error(
                "LinkAuth session creation failed: %s %s — %s",
                exc.code, exc.reason, err_body,
            )
            raise RuntimeError(
                f"LinkAuth broker returned {exc.code}: {err_body or exc.reason}"
            ) from exc
        data = json.loads(resp.read())

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
            req = urllib.request.Request(url, headers=poll_headers)
            try:
                resp = urllib.request.urlopen(req)
                data = json.loads(resp.read())
            except Exception as exc:
                # 429 (slow_down) or transient error
                read_fn = getattr(exc, "read", None)
                if read_fn and callable(read_fn):
                    err_body = cast(bytes, read_fn()).decode()
                    try:
                        err_data = json.loads(err_body)
                        if err_data.get("type", "").endswith("slow_down"):
                            session.interval = err_data.get(
                                "interval", session.interval + 5
                            )
                    except (json.JSONDecodeError, KeyError):
                        pass
                if time.time() >= deadline:
                    return None
                time.sleep(session.interval)
                continue

            status = data.get("status")

            if status == "ready":
                ciphertext = data.get("ciphertext", "")
                algorithm = data.get("algorithm", "")
                return self._decrypt(ciphertext, algorithm, scope)

            if status in ("consumed", "expired"):
                raise RuntimeError(
                    f"LinkAuth session {status} for scope '{scope}'"
                )

            # pending / confirmed → keep polling
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
            f"Set token_field= in LinkAuthAdapter."
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
