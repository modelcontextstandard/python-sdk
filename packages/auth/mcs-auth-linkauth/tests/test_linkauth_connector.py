"""Tests for LinkAuthConnector -- proxy_http, passthrough authenticate, and full flow."""

from __future__ import annotations

import base64
import json
import secrets
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from mcs.auth.challenge import AuthChallenge
from mcs.auth.linkauth import LinkAuthConnector


def encrypt_for_key(public_key_b64: str, payload: dict) -> str:
    """Hybrid-encrypt *payload* with an RSA public key (same scheme as broker)."""
    pub_key_der = base64.b64decode(public_key_b64)
    public_key = serialization.load_der_public_key(pub_key_der)

    aes_key = AESGCM.generate_key(bit_length=256)
    iv = secrets.token_bytes(12)
    plaintext = json.dumps(payload).encode()
    ciphertext = AESGCM(aes_key).encrypt(iv, plaintext, None)

    wrapped_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    inner = {
        "wrapped_key": base64.b64encode(wrapped_key).decode(),
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }
    return base64.b64encode(json.dumps(inner).encode()).decode()


class FakeBroker:
    """Minimal HTTP server that mimics the LinkAuth broker for unit tests."""

    def __init__(self) -> None:
        self._responses: list[tuple[int, dict]] = []
        self._requests: list[dict] = []

        parent = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(length)) if length else {}
                parent._requests.append({
                    "path": self.path,
                    "body": body,
                    "headers": dict(self.headers),
                })
                if parent._responses:
                    status, data = parent._responses.pop(0)
                else:
                    status, data = 200, {}
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(data).encode())

            def do_GET(self):
                parent._requests.append({
                    "path": self.path,
                    "headers": dict(self.headers),
                })
                if parent._responses:
                    status, data = parent._responses.pop(0)
                else:
                    status, data = 200, {}
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(data).encode())

            def log_message(self, *_a):
                pass

        self._server = HTTPServer(("localhost", 0), Handler)
        self.port = self._server.server_address[1]
        self.url = f"http://localhost:{self.port}"
        self._thread = Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def push_response(self, data: dict, *, status: int = 200) -> None:
        self._responses.append((status, data))

    @property
    def last_request(self) -> dict:
        return self._requests[-1] if self._requests else {}

    def stop(self) -> None:
        self._server.shutdown()


@pytest.fixture()
def broker():
    b = FakeBroker()
    yield b
    b.stop()


class TestProxyHttp:
    """Tests for LinkAuthConnector.proxy_http()."""

    def test_proxy_http_sends_correct_request(self, broker: FakeBroker):
        broker.push_response({
            "status_code": 200,
            "headers": {},
            "body": '{"result": "ok"}',
        })

        connector = LinkAuthConnector(
            broker_url=broker.url,
            api_key="test-key",
        )

        result = connector.proxy_http(
            "POST",
            "https://example.com/api",
            headers={"Authorization": "Bearer tok"},
            json_body={"key": "value"},
        )

        assert result["status_code"] == 200
        assert "result" in result.get("body", "")

        req = broker.last_request
        assert req["path"] == "/v1/proxy"
        assert req["body"]["method"] == "POST"
        assert req["body"]["url"] == "https://example.com/api"
        headers_lower = {k.lower(): v for k, v in req["headers"].items()}
        assert "test-key" in headers_lower.get("x-api-key", "")

    def test_proxy_http_raises_on_broker_error(self, broker: FakeBroker):
        broker.push_response(
            {"detail": "Forbidden"},
            status=403,
        )

        connector = LinkAuthConnector(broker_url=broker.url, api_key="bad-key")

        with pytest.raises(RuntimeError, match="Broker proxy returned 403"):
            connector.proxy_http("GET", "https://example.com")


class TestCallbackUrl:
    def test_callback_url_property(self):
        connector = LinkAuthConnector(broker_url="https://broker.example.com")
        assert connector.callback_url == "https://broker.example.com/v1/oauth/callback"


class TestPassthroughAuthenticate:
    """Tests for authenticate() in passthrough mode."""

    def test_passthrough_creates_session_with_custom_url(self, broker: FakeBroker):
        """First call with url= creates session with custom_authorize_url."""
        broker.push_response({
            "session_id": "sid-1",
            "code": "ABCD-1234",
            "url": f"{broker.url}/connect/ABCD-1234",
            "poll_token": "pt_test",
            "expires_at": "2099-01-01T00:00:00Z",
            "interval": 5,
        })

        connector = LinkAuthConnector(broker_url=broker.url, poll_timeout=0)

        with pytest.raises(AuthChallenge):
            connector.authenticate(
                "gmail:connect",
                url="https://auth0.example.com/connect?ticket=t1",
                callback_params=["connect_code"],
                state="my-state",
            )

        req = broker.last_request
        body = req["body"]
        assert body["custom_authorize_url"] == "https://auth0.example.com/connect?ticket=t1"
        assert body["custom_callback_params"] == ["connect_code"]
        assert body["custom_state"] == "my-state"

    def test_default_authenticate_no_custom_fields(self, broker: FakeBroker):
        """Default authenticate() does not send custom redirect fields."""
        broker.push_response({
            "session_id": "sid-2",
            "code": "EFGH-5678",
            "url": f"{broker.url}/connect/EFGH-5678",
            "poll_token": "pt_test2",
            "expires_at": "2099-01-01T00:00:00Z",
            "interval": 5,
        })

        connector = LinkAuthConnector(broker_url=broker.url, poll_timeout=0)

        with pytest.raises(AuthChallenge):
            connector.authenticate("gmail")

        req = broker.last_request
        body = req["body"]
        assert "custom_authorize_url" not in body
        assert "custom_callback_params" not in body
        assert "custom_state" not in body


# ---------------------------------------------------------------------------
# Full authenticate → poll → decrypt round-trip
# ---------------------------------------------------------------------------

class TestFullAuthenticateFlow:
    """End-to-end: session creation → poll → hybrid decryption → token."""

    def test_single_call_immediate_ready(self, broker: FakeBroker):
        """With poll_timeout > 0 the connector polls immediately and returns."""
        connector = LinkAuthConnector(
            broker_url=broker.url, poll_timeout=5, poll_interval=0,
        )

        broker.push_response({
            "session_id": "sid-full-1",
            "code": "TEST-1234",
            "url": f"{broker.url}/connect/TEST-1234",
            "poll_token": "pt_full",
            "expires_at": "2099-01-01T00:00:00Z",
            "interval": 0,
        })

        ciphertext = encrypt_for_key(
            connector._public_key_b64,
            {"refresh_token": "rt_test_123", "access_token": "at_test"},
        )
        broker.push_response({
            "status": "ready",
            "ciphertext": ciphertext,
            "algorithm": "RSA-OAEP-256+AES-256-GCM",
            "expires_at": "2099-01-01T00:00:00Z",
        })

        token = connector.authenticate("gmail")
        assert token == "rt_test_123"

    def test_multi_call_challenge_then_ready(self, broker: FakeBroker):
        """poll_timeout=0: first call raises AuthChallenge, second returns token."""
        connector = LinkAuthConnector(broker_url=broker.url, poll_timeout=0)

        broker.push_response({
            "session_id": "sid-full-2",
            "code": "ABCD-5678",
            "url": f"{broker.url}/connect/ABCD-5678",
            "poll_token": "pt_full2",
            "expires_at": "2099-01-01T00:00:00Z",
            "interval": 0,
        })

        with pytest.raises(AuthChallenge) as exc_info:
            connector.authenticate("gmail")
        assert "ABCD-5678" in str(exc_info.value)

        ciphertext = encrypt_for_key(
            connector._public_key_b64,
            {"access_token": "ya29.google"},
        )
        broker.push_response({
            "status": "ready",
            "ciphertext": ciphertext,
            "algorithm": "RSA-OAEP-256+AES-256-GCM",
            "expires_at": "2099-01-01T00:00:00Z",
        })

        token = connector.authenticate("gmail")
        assert token == "ya29.google"

    def test_three_calls_pending_then_ready(self, broker: FakeBroker):
        """Challenge → pending (challenge again) → ready (token)."""
        connector = LinkAuthConnector(broker_url=broker.url, poll_timeout=0)

        broker.push_response({
            "session_id": "sid-pend",
            "code": "PEND-1234",
            "url": f"{broker.url}/connect/PEND-1234",
            "poll_token": "pt_pend",
            "expires_at": "2099-01-01T00:00:00Z",
            "interval": 0,
        })

        # Call 1 — session created, challenge raised
        with pytest.raises(AuthChallenge):
            connector.authenticate("slack")

        broker.push_response({
            "status": "pending",
            "expires_at": "2099-01-01T00:00:00Z",
            "interval": 0,
        })

        # Call 2 — pending, challenge raised again
        with pytest.raises(AuthChallenge):
            connector.authenticate("slack")

        ciphertext = encrypt_for_key(
            connector._public_key_b64,
            {"access_token": "xoxb-slack"},
        )
        broker.push_response({
            "status": "ready",
            "ciphertext": ciphertext,
            "algorithm": "RSA-OAEP-256+AES-256-GCM",
            "expires_at": "2099-01-01T00:00:00Z",
        })

        # Call 3 — ready, token returned
        assert connector.authenticate("slack") == "xoxb-slack"

    def test_token_caching(self, broker: FakeBroker):
        """Second call for same scope returns cached token without broker call."""
        connector = LinkAuthConnector(
            broker_url=broker.url, poll_timeout=5, poll_interval=0,
        )

        broker.push_response({
            "session_id": "sid-cache",
            "code": "CACH-1234",
            "url": f"{broker.url}/connect/CACH-1234",
            "poll_token": "pt_cache",
            "expires_at": "2099-01-01T00:00:00Z",
            "interval": 0,
        })

        ciphertext = encrypt_for_key(
            connector._public_key_b64,
            {"api_key": "sk-cached-key"},
        )
        broker.push_response({
            "status": "ready",
            "ciphertext": ciphertext,
            "algorithm": "RSA-OAEP-256+AES-256-GCM",
            "expires_at": "2099-01-01T00:00:00Z",
        })

        token1 = connector.authenticate("openai")
        token2 = connector.authenticate("openai")
        assert token1 == token2 == "sk-cached-key"

    def test_token_field_override(self, broker: FakeBroker):
        """Explicit token_field= extracts the correct field from decrypted payload."""
        connector = LinkAuthConnector(
            broker_url=broker.url,
            poll_timeout=5,
            poll_interval=0,
            token_field="custom_field",
        )

        broker.push_response({
            "session_id": "sid-tf",
            "code": "FIEL-1234",
            "url": f"{broker.url}/connect/FIEL-1234",
            "poll_token": "pt_tf",
            "expires_at": "2099-01-01T00:00:00Z",
            "interval": 0,
        })

        ciphertext = encrypt_for_key(
            connector._public_key_b64,
            {"custom_field": "my-custom-value", "other": "ignored"},
        )
        broker.push_response({
            "status": "ready",
            "ciphertext": ciphertext,
            "algorithm": "RSA-OAEP-256+AES-256-GCM",
            "expires_at": "2099-01-01T00:00:00Z",
        })

        assert connector.authenticate("myservice") == "my-custom-value"

    def test_expired_session_raises_runtime_error(self, broker: FakeBroker):
        connector = LinkAuthConnector(broker_url=broker.url, poll_timeout=0)

        broker.push_response({
            "session_id": "sid-exp",
            "code": "EXPR-1234",
            "url": f"{broker.url}/connect/EXPR-1234",
            "poll_token": "pt_exp",
            "expires_at": "2099-01-01T00:00:00Z",
            "interval": 0,
        })

        with pytest.raises(AuthChallenge):
            connector.authenticate("gmail")

        broker.push_response({
            "status": "expired",
            "expires_at": "2020-01-01T00:00:00Z",
        })

        with pytest.raises(RuntimeError, match="expired"):
            connector.authenticate("gmail")


# ---------------------------------------------------------------------------
# Passthrough decrypt flow
# ---------------------------------------------------------------------------

class TestPassthroughDecryptFlow:
    """Passthrough: session with custom URL → poll → decrypt captured params."""

    def test_passthrough_returns_captured_param(self, broker: FakeBroker):
        connector = LinkAuthConnector(broker_url=broker.url, poll_timeout=0)

        broker.push_response({
            "session_id": "sid-pt-1",
            "code": "PASS-1234",
            "url": f"{broker.url}/connect/PASS-1234",
            "poll_token": "pt_pt1",
            "expires_at": "2099-01-01T00:00:00Z",
            "interval": 0,
        })

        with pytest.raises(AuthChallenge):
            connector.authenticate(
                "gmail:connect",
                url="https://auth0.example.com/connect?ticket=t1",
                callback_params=["connect_code"],
                state="state-abc",
            )

        ciphertext = encrypt_for_key(
            connector._public_key_b64,
            {"connect_code": "cc-xyz-123"},
        )
        broker.push_response({
            "status": "ready",
            "ciphertext": ciphertext,
            "algorithm": "RSA-OAEP-256+AES-256-GCM",
            "expires_at": "2099-01-01T00:00:00Z",
        })

        result = connector.authenticate(
            "gmail:connect",
            url="https://auth0.example.com/connect?ticket=t1",
            callback_params=["connect_code"],
            state="state-abc",
        )
        assert result == "cc-xyz-123"

    def test_passthrough_and_standard_are_independent(self, broker: FakeBroker):
        """Passthrough session does not collide with a standard session
        for the same base scope."""
        connector = LinkAuthConnector(broker_url=broker.url, poll_timeout=0)

        # Standard session for "gmail"
        broker.push_response({
            "session_id": "sid-std",
            "code": "STND-1234",
            "url": f"{broker.url}/connect/STND-1234",
            "poll_token": "pt_std",
            "expires_at": "2099-01-01T00:00:00Z",
            "interval": 0,
        })

        with pytest.raises(AuthChallenge):
            connector.authenticate("gmail")

        # Passthrough session for "gmail:connect" (different cache_key)
        broker.push_response({
            "session_id": "sid-pt-ind",
            "code": "PTHR-5678",
            "url": f"{broker.url}/connect/PTHR-5678",
            "poll_token": "pt_ptind",
            "expires_at": "2099-01-01T00:00:00Z",
            "interval": 0,
        })

        with pytest.raises(AuthChallenge):
            connector.authenticate(
                "gmail:connect",
                url="https://example.com/connect",
                callback_params=["code"],
                state="st-1",
            )

        # Both sessions exist independently
        assert "gmail" in connector._sessions
        assert "gmail:connect:redirect:st-1" in connector._sessions


# ---------------------------------------------------------------------------
# Compatibility with new broker response fields
# ---------------------------------------------------------------------------

class TestNewBrokerResponseFields:
    """Connector gracefully ignores extra fields from updated broker."""

    def test_session_with_callback_secret_and_webhook_url(self, broker: FakeBroker):
        """New fields callback_secret, webhook_url must not break session creation."""
        broker.push_response({
            "session_id": "sid-new",
            "code": "NEW-1234",
            "url": f"{broker.url}/connect/NEW-1234",
            "poll_token": "pt_new",
            "expires_at": "2099-01-01T00:00:00Z",
            "interval": 5,
            "callback_secret": "cs_supersecretvalue",
            "webhook_url": "https://broker.example.com/v1/sessions/sid-new/webhook?token=wt_xyz",
        })

        connector = LinkAuthConnector(broker_url=broker.url, poll_timeout=0)

        with pytest.raises(AuthChallenge) as exc_info:
            connector.authenticate("gmail")

        assert exc_info.value.code == "NEW-1234"

    def test_full_flow_with_extra_response_fields(self, broker: FakeBroker):
        """Full encrypt/decrypt flow works despite extra broker fields."""
        connector = LinkAuthConnector(
            broker_url=broker.url, poll_timeout=5, poll_interval=0,
        )

        broker.push_response({
            "session_id": "sid-extra",
            "code": "EXTR-1234",
            "url": f"{broker.url}/connect/EXTR-1234",
            "poll_token": "pt_extra",
            "expires_at": "2099-01-01T00:00:00Z",
            "interval": 0,
            "callback_secret": "cs_test123",
            "webhook_url": None,
        })

        ciphertext = encrypt_for_key(
            connector._public_key_b64,
            {"api_key": "sk-from-new-broker"},
        )
        broker.push_response({
            "status": "ready",
            "ciphertext": ciphertext,
            "algorithm": "RSA-OAEP-256+AES-256-GCM",
            "expires_at": "2099-01-01T00:00:00Z",
        })

        assert connector.authenticate("openai") == "sk-from-new-broker"


# ---------------------------------------------------------------------------
# RFC 8628 slow_down and error handling
# ---------------------------------------------------------------------------

class TestPollingErrorHandling:
    """429 slow_down, expired sessions, and transient errors during polling."""

    def test_slow_down_updates_interval(self, broker: FakeBroker):
        """429 with slow_down type increases the session's polling interval."""
        connector = LinkAuthConnector(broker_url=broker.url, poll_timeout=0)

        broker.push_response({
            "session_id": "sid-slow",
            "code": "SLOW-1234",
            "url": f"{broker.url}/connect/SLOW-1234",
            "poll_token": "pt_slow",
            "expires_at": "2099-01-01T00:00:00Z",
            "interval": 5,
        })

        with pytest.raises(AuthChallenge):
            connector.authenticate("gmail")

        broker.push_response(
            {
                "type": "urn:ietf:params:oauth:error:slow_down",
                "title": "Slow Down",
                "status": 429,
                "interval": 15,
            },
            status=429,
        )

        with pytest.raises(AuthChallenge):
            connector.authenticate("gmail")

        assert connector._sessions["gmail"].interval == 15

    def test_slow_down_then_ready(self, broker: FakeBroker):
        """Full cycle: create → 429 slow_down → ready → token."""
        connector = LinkAuthConnector(broker_url=broker.url, poll_timeout=0)

        broker.push_response({
            "session_id": "sid-sdr",
            "code": "SDRY-1234",
            "url": f"{broker.url}/connect/SDRY-1234",
            "poll_token": "pt_sdr",
            "expires_at": "2099-01-01T00:00:00Z",
            "interval": 0,
        })

        with pytest.raises(AuthChallenge):
            connector.authenticate("gmail")

        # Poll → 429 slow_down
        broker.push_response(
            {
                "type": "urn:ietf:params:oauth:error:slow_down",
                "title": "Slow Down",
                "status": 429,
                "interval": 10,
            },
            status=429,
        )

        with pytest.raises(AuthChallenge):
            connector.authenticate("gmail")

        # Poll → ready
        ciphertext = encrypt_for_key(
            connector._public_key_b64,
            {"access_token": "ya29.after-slowdown"},
        )
        broker.push_response({
            "status": "ready",
            "ciphertext": ciphertext,
            "algorithm": "RSA-OAEP-256+AES-256-GCM",
            "expires_at": "2099-01-01T00:00:00Z",
        })

        assert connector.authenticate("gmail") == "ya29.after-slowdown"
