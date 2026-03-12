"""Tests for MailsendToolDriver -- uses a fake adapter (no real connection)."""

from __future__ import annotations

import json

import pytest

from mcs.driver.mailsend import MailsendToolDriver


class FakeMailsendAdapter:
    """Satisfies MailsendPort without touching the network."""

    def send_message(self, *, to, subject, body, cc="", bcc="", reply_to="") -> str:
        recipients = [a.strip() for a in to.split(",") if a.strip()]
        if cc:
            recipients += [a.strip() for a in cc.split(",") if a.strip()]
        if bcc:
            recipients += [a.strip() for a in bcc.split(",") if a.strip()]
        return json.dumps({
            "status": "sent", "from": "test@example.com",
            "recipients": recipients, "subject": subject,
        })

    def send_html_message(self, *, to, subject, html_body, text_body="",
                          cc="", bcc="", reply_to="") -> str:
        recipients = [a.strip() for a in to.split(",") if a.strip()]
        return json.dumps({
            "status": "sent", "from": "test@example.com",
            "recipients": recipients, "subject": subject,
        })

    def check_connection(self) -> str:
        return json.dumps({"status": "ok", "server": "smtp.test.local", "port": 587})


@pytest.fixture()
def td() -> MailsendToolDriver:
    return MailsendToolDriver(_adapter=FakeMailsendAdapter())


class TestListTools:

    def test_returns_three_tools(self, td: MailsendToolDriver):
        assert len(td.list_tools()) == 3

    def test_tool_names(self, td: MailsendToolDriver):
        names = {t.name for t in td.list_tools()}
        assert names == {"send_message", "send_html_message", "check_connection"}


class TestExecuteTool:

    def test_send_message(self, td: MailsendToolDriver):
        result = json.loads(td.execute_tool("send_message", {
            "to": "alice@example.com", "subject": "Hello", "body": "Hi!",
        }))
        assert result["status"] == "sent"

    def test_send_message_with_cc_bcc(self, td: MailsendToolDriver):
        result = json.loads(td.execute_tool("send_message", {
            "to": "alice@example.com", "subject": "FYI", "body": "note",
            "cc": "bob@example.com", "bcc": "carol@example.com",
        }))
        assert len(result["recipients"]) == 3

    def test_send_html_message(self, td: MailsendToolDriver):
        result = json.loads(td.execute_tool("send_html_message", {
            "to": "alice@example.com", "subject": "News", "html_body": "<h1>Hi</h1>",
        }))
        assert result["status"] == "sent"

    def test_check_connection(self, td: MailsendToolDriver):
        result = json.loads(td.execute_tool("check_connection", {}))
        assert result["status"] == "ok"

    def test_unknown_tool_raises(self, td: MailsendToolDriver):
        with pytest.raises(ValueError, match="Unknown tool"):
            td.execute_tool("nonexistent", {})


class TestDriverMeta:

    def test_meta_attributes(self, td: MailsendToolDriver):
        assert td.meta.name == "Mailsend MCS ToolDriver"
        assert td.meta.bindings[0].capability == "mailsend"
        assert td.meta.bindings[0].adapter == "*"


class TestConstructor:

    def test_unknown_adapter_raises(self):
        with pytest.raises(ValueError, match="Unknown mailsend adapter"):
            MailsendToolDriver(adapter="nonexistent")

    def test_accepts_adapter_injection(self):
        td = MailsendToolDriver(_adapter=FakeMailsendAdapter())
        assert td.list_tools()
