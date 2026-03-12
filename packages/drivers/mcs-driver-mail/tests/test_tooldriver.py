"""Tests for MailToolDriver -- composite of mailread + mailsend."""

from __future__ import annotations

import json

import pytest

from mcs.driver.mail import MailToolDriver
from mcs.driver.mailread import MailreadToolDriver
from mcs.driver.mailsend import MailsendToolDriver


class FakeMailboxAdapter:
    def list_folders(self) -> str:
        return json.dumps(["INBOX", "Sent"])

    def list_messages(self, folder="INBOX", *, limit=20) -> str:
        return json.dumps([{"uid": 1, "subject": "Test"}])

    def fetch_message(self, uid, folder="INBOX") -> str:
        return json.dumps({"uid": uid, "body": "content"})

    def move_message(self, uid, destination, folder="INBOX") -> str:
        return json.dumps({"moved": uid})

    def set_flags(self, uid, flags, *, remove=False, folder="INBOX") -> str:
        return json.dumps({"uid": uid})

    def create_folder(self, name) -> str:
        return json.dumps({"created": name})

    def search_messages(self, criteria="ALL", folder="INBOX", *, limit=20) -> str:
        return json.dumps([])


class FakeMailsendAdapter:
    def send_message(self, *, to, subject, body, cc="", bcc="", reply_to="") -> str:
        return json.dumps({"status": "sent", "recipients": [to], "subject": subject})

    def send_html_message(self, *, to, subject, html_body, text_body="",
                          cc="", bcc="", reply_to="") -> str:
        return json.dumps({"status": "sent", "recipients": [to], "subject": subject})

    def check_connection(self) -> str:
        return json.dumps({"status": "ok", "server": "smtp.test", "port": 587})


@pytest.fixture()
def td() -> MailToolDriver:
    read_td = MailreadToolDriver(_adapter=FakeMailboxAdapter())
    send_td = MailsendToolDriver(_adapter=FakeMailsendAdapter())
    return MailToolDriver(_read_driver=read_td, _send_driver=send_td)


class TestComposite:

    def test_has_ten_tools(self, td: MailToolDriver):
        assert len(td.list_tools()) == 10

    def test_contains_read_tools(self, td: MailToolDriver):
        names = {t.name for t in td.list_tools()}
        assert "list_folders" in names
        assert "fetch_message" in names
        assert "search_messages" in names

    def test_contains_send_tools(self, td: MailToolDriver):
        names = {t.name for t in td.list_tools()}
        assert "send_message" in names
        assert "send_html_message" in names
        assert "check_connection" in names

    def test_execute_read_tool(self, td: MailToolDriver):
        result = json.loads(td.execute_tool("list_folders", {}))
        assert "INBOX" in result

    def test_execute_send_tool(self, td: MailToolDriver):
        result = json.loads(td.execute_tool("send_message", {
            "to": "alice@example.com", "subject": "Hi", "body": "Hello",
        }))
        assert result["status"] == "sent"

    def test_execute_check_connection(self, td: MailToolDriver):
        result = json.loads(td.execute_tool("check_connection", {}))
        assert result["status"] == "ok"

    def test_unknown_tool_raises(self, td: MailToolDriver):
        with pytest.raises(ValueError, match="Unknown tool"):
            td.execute_tool("nonexistent", {})


class TestDriverMeta:

    def test_meta_name(self, td: MailToolDriver):
        assert td.meta.name == "Mail MCS ToolDriver"

    def test_meta_has_two_bindings(self, td: MailToolDriver):
        assert len(td.meta.bindings) == 2
        capabilities = {b.capability for b in td.meta.bindings}
        assert capabilities == {"mailread", "mailsend"}
