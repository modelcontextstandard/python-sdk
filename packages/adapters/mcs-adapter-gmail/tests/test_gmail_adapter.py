"""Tests for GmailAdapter -- mocks HttpAdapter, no network needed."""

from __future__ import annotations

import base64
import json

import pytest

from mcs.adapter.gmail import GmailAdapter


class FakeHttp:
    """Minimal HttpAdapter stub that returns canned JSON responses."""

    def __init__(self) -> None:
        self._routes: dict[str, str] = {}

    def register(self, method: str, url_suffix: str, response: dict) -> None:
        self._routes[f"{method}:{url_suffix}"] = json.dumps(response)

    def request(self, method, url, *, params=None, json_body=None, headers=None, timeout=None):
        # Match by suffix
        for key, resp in self._routes.items():
            m, suffix = key.split(":", 1)
            if m == method.upper() and url.endswith(suffix):
                return resp
        raise ValueError(f"No route for {method} {url}")


@pytest.fixture()
def http() -> FakeHttp:
    h = FakeHttp()
    # Profile
    h.register("GET", "/profile", {"emailAddress": "alice@gmail.com"})
    # Labels
    h.register("GET", "/labels", {
        "labels": [
            {"id": "INBOX", "name": "INBOX"},
            {"id": "SENT", "name": "SENT"},
            {"id": "Label_1", "name": "Projects"},
        ]
    })
    return h


@pytest.fixture()
def adapter(http: FakeHttp) -> GmailAdapter:
    return GmailAdapter(access_token="test-token", sender_name="Alice", _http=http)


class TestMailboxPort:

    def test_list_folders(self, adapter: GmailAdapter):
        result = json.loads(adapter.list_folders())
        assert "INBOX" in result
        assert "Projects" in result
        assert result == sorted(result)

    def test_list_messages(self, adapter: GmailAdapter, http: FakeHttp):
        # Register messages list + one metadata fetch
        http.register("GET", "/messages", {
            "messages": [{"id": "msg1", "threadId": "t1"}],
        })
        http.register("GET", "/messages/msg1", {
            "id": "msg1",
            "payload": {"headers": [
                {"name": "From", "value": "bob@example.com"},
                {"name": "Subject", "value": "Hello"},
                {"name": "Date", "value": "Mon, 12 Mar 2026 10:00:00 +0000"},
            ]},
            "snippet": "Hi there",
            "labelIds": ["INBOX"],
        })
        result = json.loads(adapter.list_messages("INBOX", limit=5))
        assert len(result) == 1
        assert result[0]["uid"] == "msg1"
        assert result[0]["subject"] == "Hello"

    def test_fetch_message(self, adapter: GmailAdapter, http: FakeHttp):
        body_data = base64.urlsafe_b64encode(b"Hello world").decode("ascii")
        http.register("GET", "/messages/msg2", {
            "id": "msg2",
            "threadId": "t2",
            "labelIds": ["INBOX"],
            "snippet": "Hello world",
            "payload": {
                "mimeType": "text/plain",
                "headers": [
                    {"name": "From", "value": "bob@example.com"},
                    {"name": "To", "value": "alice@gmail.com"},
                    {"name": "Subject", "value": "Test"},
                    {"name": "Date", "value": "Mon, 12 Mar 2026"},
                ],
                "body": {"size": 11, "data": body_data},
            },
        })
        result = json.loads(adapter.fetch_message("msg2"))
        assert result["body"] == "Hello world"
        assert result["subject"] == "Test"

    def test_move_message(self, adapter: GmailAdapter, http: FakeHttp):
        http.register("POST", "/messages/msg3/modify", {
            "id": "msg3",
            "labelIds": ["TRASH"],
        })
        result = json.loads(adapter.move_message("msg3", "TRASH", "INBOX"))
        assert result["uid"] == "msg3"
        assert "TRASH" in result["labels"]

    def test_create_folder(self, adapter: GmailAdapter, http: FakeHttp):
        http.register("POST", "/labels", {"id": "Label_99", "name": "Archive"})
        result = json.loads(adapter.create_folder("Archive"))
        assert result["name"] == "Archive"

    def test_set_flags_starred(self, adapter: GmailAdapter, http: FakeHttp):
        http.register("POST", "/messages/msg4/modify", {
            "id": "msg4",
            "labelIds": ["INBOX", "STARRED"],
        })
        result = json.loads(adapter.set_flags("msg4", "STARRED"))
        assert "STARRED" in result["labels"]


class TestMailsendPort:

    def test_send_message(self, adapter: GmailAdapter, http: FakeHttp):
        http.register("POST", "/messages/send", {
            "id": "sent1",
            "threadId": "t_sent1",
            "labelIds": ["SENT"],
        })
        result = json.loads(adapter.send_message(
            to="bob@example.com",
            subject="Hi",
            body="Hello Bob!",
        ))
        assert result["status"] == "sent"
        assert result["id"] == "sent1"

    def test_send_html_message(self, adapter: GmailAdapter, http: FakeHttp):
        http.register("POST", "/messages/send", {
            "id": "sent2",
            "threadId": "t_sent2",
            "labelIds": ["SENT"],
        })
        result = json.loads(adapter.send_html_message(
            to="bob@example.com",
            subject="Hi",
            html_body="<h1>Hello</h1>",
            text_body="Hello",
        ))
        assert result["status"] == "sent"


class TestCallableToken:

    def test_callable_access_token(self, http: FakeHttp):
        call_count = 0

        def token_provider() -> str:
            nonlocal call_count
            call_count += 1
            return f"token-{call_count}"

        adapter = GmailAdapter(access_token=token_provider, _http=http)
        adapter.list_folders()
        assert call_count >= 1

    def test_credential_provider(self, http: FakeHttp):
        """A CredentialProvider can replace access_token."""

        class FakeCredential:
            def get_token(self, scope: str) -> str:
                assert scope == "gmail"
                return "cred-provider-token"

        adapter = GmailAdapter(_credential=FakeCredential(), _http=http)
        adapter.list_folders()

    def test_neither_token_nor_credential_raises(self):
        with pytest.raises(ValueError, match="Either 'access_token' or '_credential'"):
            GmailAdapter()
