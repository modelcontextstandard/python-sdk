"""Integration tests: Auth0Provider + LinkAuthConnector through FakeBroker.

Verifies the complete flow:
 - LinkAuthConnector obtains tokens from a broker (FakeBroker)
 - Auth0Provider uses the connector as its AuthPort
 - Token exchange, Connected Accounts setup via proxy_http, and
   passthrough redirects all work end-to-end.

Requires: mcs-auth-auth0, mcs-adapter-http (skipped if not installed).
"""

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

auth0_mod = pytest.importorskip("mcs.auth.auth0")
http_mod = pytest.importorskip("mcs.adapter.http")

from mcs.adapter.http import HttpResponse
from mcs.auth.auth0 import Auth0Provider
from mcs.auth.challenge import AuthChallenge
from mcs.auth.linkauth import LinkAuthConnector


# ---------------------------------------------------------------------------
# Test infrastructure
# ---------------------------------------------------------------------------

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
    """Minimal HTTP server that mimics the LinkAuth broker."""

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

    @property
    def requests(self) -> list[dict]:
        return self._requests

    def stop(self) -> None:
        self._server.shutdown()


@pytest.fixture()
def broker():
    b = FakeBroker()
    yield b
    b.stop()


def _http_response(data: dict, *, status_code: int | None = None) -> HttpResponse:
    text = json.dumps(data)
    if status_code is None:
        status_code = 400 if "error" in data else 200
    return HttpResponse(
        status_code=status_code,
        text=text,
        content=text.encode(),
        headers={"Content-Type": "application/json"},
        reason="",
    )


class FakeHttp:
    """Stub HTTP transport for Auth0 API calls."""

    def __init__(self) -> None:
        self._responses: list[HttpResponse] = []

    def push(self, data: dict, *, status_code: int | None = None) -> None:
        self._responses.append(_http_response(data, status_code=status_code))

    def request(self, method, url, *, json_body=None, headers=None, **kw):
        if self._responses:
            return self._responses.pop(0)
        return _http_response({"error": "no_response"}, status_code=500)


# ---------------------------------------------------------------------------
# Basic OAuth flow: LinkAuthConnector → Auth0Provider Token Exchange
# ---------------------------------------------------------------------------

class TestBasicTokenAcquisition:
    """Auth0Provider obtains refresh_token via LinkAuthConnector,
    then exchanges it for an external access_token via Token Vault."""

    def test_full_flow_challenge_then_token(self, broker: FakeBroker):
        http = FakeHttp()
        conn = LinkAuthConnector(broker_url=broker.url, poll_timeout=0)

        provider = Auth0Provider(
            domain="test.auth0.com",
            client_id="c",
            client_secret="s",
            _auth=conn,
            _http=http,
        )

        # 1. LinkAuthConnector creates session → AuthChallenge
        broker.push_response({
            "session_id": "sid-a0-1",
            "code": "AUTH-1234",
            "url": f"{broker.url}/connect/AUTH-1234",
            "poll_token": "pt_a0",
            "expires_at": "2099-01-01T00:00:00Z",
            "interval": 0,
        })

        with pytest.raises(AuthChallenge) as exc_info:
            provider.get_token("gmail")
        assert "AUTH-1234" in str(exc_info.value)

        # 2. Broker returns encrypted refresh_token
        ciphertext = encrypt_for_key(
            conn._public_key_b64,
            {"refresh_token": "rt_from_broker"},
        )
        broker.push_response({
            "status": "ready",
            "ciphertext": ciphertext,
            "algorithm": "RSA-OAEP-256+AES-256-GCM",
            "expires_at": "2099-01-01T00:00:00Z",
        })

        # 3. Auth0 Token Vault exchange succeeds
        http.push({"access_token": "ya29.google", "expires_in": 3600})

        token = provider.get_token("gmail")
        assert token == "ya29.google"

    def test_token_cached_after_exchange(self, broker: FakeBroker):
        """Second call for same scope returns cached token, no broker interaction."""
        http = FakeHttp()
        conn = LinkAuthConnector(
            broker_url=broker.url, poll_timeout=5, poll_interval=0,
        )

        provider = Auth0Provider(
            domain="test.auth0.com",
            client_id="c",
            client_secret="s",
            _auth=conn,
            _http=http,
        )

        # Session creation + ready
        broker.push_response({
            "session_id": "sid-a0-c",
            "code": "CACH-1234",
            "url": f"{broker.url}/connect/CACH-1234",
            "poll_token": "pt_c",
            "expires_at": "2099-01-01T00:00:00Z",
            "interval": 0,
        })
        ciphertext = encrypt_for_key(
            conn._public_key_b64,
            {"refresh_token": "rt_cached"},
        )
        broker.push_response({
            "status": "ready",
            "ciphertext": ciphertext,
            "algorithm": "RSA-OAEP-256+AES-256-GCM",
            "expires_at": "2099-01-01T00:00:00Z",
        })

        http.push({"access_token": "ya29.first", "expires_in": 3600})

        assert provider.get_token("gmail") == "ya29.first"

        # Second call for same scope — cached, no broker or http call
        assert provider.get_token("gmail") == "ya29.first"

    def test_different_scope_reuses_refresh_token(self, broker: FakeBroker):
        """Refresh token obtained once is reused for different scope exchanges."""
        http = FakeHttp()
        conn = LinkAuthConnector(
            broker_url=broker.url, poll_timeout=5, poll_interval=0,
        )

        provider = Auth0Provider(
            domain="test.auth0.com",
            client_id="c",
            client_secret="s",
            _auth=conn,
            _http=http,
        )

        # One broker session for the refresh token
        broker.push_response({
            "session_id": "sid-multi",
            "code": "MULT-1234",
            "url": f"{broker.url}/connect/MULT-1234",
            "poll_token": "pt_m",
            "expires_at": "2099-01-01T00:00:00Z",
            "interval": 0,
        })
        ciphertext = encrypt_for_key(
            conn._public_key_b64,
            {"refresh_token": "rt_multi"},
        )
        broker.push_response({
            "status": "ready",
            "ciphertext": ciphertext,
            "algorithm": "RSA-OAEP-256+AES-256-GCM",
            "expires_at": "2099-01-01T00:00:00Z",
        })

        http.push({"access_token": "ya29.gmail", "expires_in": 3600})
        assert provider.get_token("gmail") == "ya29.gmail"

        # Second scope — no broker call, refresh_token reused
        http.push({"access_token": "ya29.drive", "expires_in": 3600})
        assert provider.get_token("google-drive") == "ya29.drive"


# ---------------------------------------------------------------------------
# Connected Accounts flow via proxy_http
# ---------------------------------------------------------------------------

class TestConnectedAccountsViaProxy:
    """Connected Accounts setup using LinkAuthConnector.proxy_http()
    to route /connect and /complete through the broker proxy."""

    def test_connected_accounts_via_proxy(self, broker: FakeBroker):
        http = FakeHttp()
        conn = LinkAuthConnector(
            broker_url=broker.url,
            api_key="test-api-key",
            poll_timeout=0,
        )

        provider = Auth0Provider(
            domain="test.auth0.com",
            client_id="c",
            client_secret="s",
            refresh_token="rt_existing",
            connection_scopes={"gmail": ["https://mail.google.com/", "openid"]},
            _auth=conn,
            _http=http,
        )

        # --- Call 1: Token Vault → not_found → start Connected Accounts ---

        # 1a. Token Vault exchange fails
        http.push({
            "error": "federated_connection_refresh_token_not_found",
            "error_description": "Federated connection Refresh Token not found.",
        })
        # 1b. MRRT exchange succeeds
        http.push({"access_token": "ma_tok", "scope": "create:me:connected_accounts"})

        # 1c. POST /connect via proxy_http → broker proxy response
        connect_resp = json.dumps({
            "connect_uri": "https://test.auth0.com/connected-accounts/connect",
            "connect_params": {"ticket": "tkt-123"},
            "auth_session": "session-abc",
            "expires_in": 300,
        })
        broker.push_response({
            "status_code": 200,
            "headers": {"Content-Type": "application/json"},
            "body": connect_resp,
        })

        # 1d. LinkAuthConnector creates passthrough session → AuthChallenge
        broker.push_response({
            "session_id": "sid-ca-1",
            "code": "CONN-1234",
            "url": f"{broker.url}/connect/CONN-1234",
            "poll_token": "pt_ca",
            "expires_at": "2099-01-01T00:00:00Z",
            "interval": 0,
            "callback_secret": "cs_test",
        })

        with pytest.raises(AuthChallenge):
            provider.get_token("gmail")

        assert provider._ca_pending is not None

        # Verify proxy_http was called for /connect
        proxy_req = [r for r in broker.requests if r["path"] == "/v1/proxy"]
        assert len(proxy_req) == 1
        assert "connected-accounts/connect" in proxy_req[0]["body"]["url"]

        # --- Call 2: Complete the Connected Account ---

        # 2a. Token Vault still fails (triggers _ensure_connected_account)
        http.push({
            "error": "federated_connection_refresh_token_not_found",
            "error_description": "...",
        })

        # 2b. Passthrough session returns encrypted connect_code
        ciphertext = encrypt_for_key(
            conn._public_key_b64,
            {"connect_code": "cc-from-broker"},
        )
        broker.push_response({
            "status": "ready",
            "ciphertext": ciphertext,
            "algorithm": "RSA-OAEP-256+AES-256-GCM",
            "expires_at": "2099-01-01T00:00:00Z",
        })

        # 2c. POST /complete via proxy_http → success
        complete_resp = json.dumps({
            "id": "cac_test123",
            "connection": "google-oauth2",
        })
        broker.push_response({
            "status_code": 200,
            "headers": {"Content-Type": "application/json"},
            "body": complete_resp,
        })

        # 2d. Token Vault retry succeeds
        http.push({"access_token": "ya29.final", "expires_in": 3600})

        token = provider.get_token("gmail")
        assert token == "ya29.final"
        assert provider._ca_pending is None

    def test_proxy_uses_api_key(self, broker: FakeBroker):
        """proxy_http calls include X-API-Key header."""
        conn = LinkAuthConnector(
            broker_url=broker.url,
            api_key="my-secret-key",
        )

        broker.push_response({
            "status_code": 200,
            "headers": {},
            "body": "{}",
        })

        conn.proxy_http("GET", "https://example.com/test")

        req = broker.last_request
        headers_lower = {k.lower(): v for k, v in req["headers"].items()}
        assert headers_lower.get("x-api-key") == "my-secret-key"

    def test_callback_url_from_connector(self, broker: FakeBroker):
        """Auth0Provider reads callback_url from LinkAuthConnector."""
        conn = LinkAuthConnector(broker_url="https://broker.example.com")

        provider = Auth0Provider(
            domain="test.auth0.com",
            client_id="c",
            client_secret="s",
            _auth=conn,
            _http=FakeHttp(),
        )

        assert provider._get_callback_url() == "https://broker.example.com/v1/oauth/callback"
