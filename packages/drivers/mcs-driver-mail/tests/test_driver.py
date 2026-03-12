"""Tests for MailDriver (composite HybridDriver)."""

from __future__ import annotations

import json

import pytest

from mcs.driver.mail import MailDriver, MailToolDriver
from mcs.driver.mailread import MailreadToolDriver
from mcs.driver.mailsend import MailsendToolDriver


class FakeMailboxAdapter:
    def list_folders(self) -> str:
        return json.dumps(["INBOX"])

    def list_messages(self, folder="INBOX", *, limit=20) -> str:
        return json.dumps([])

    def fetch_message(self, uid, folder="INBOX") -> str:
        return json.dumps({"uid": uid})

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
        return json.dumps({"status": "sent"})

    def send_html_message(self, *, to, subject, html_body, text_body="",
                          cc="", bcc="", reply_to="") -> str:
        return json.dumps({"status": "sent"})




@pytest.fixture()
def driver() -> MailDriver:
    read_td = MailreadToolDriver(_adapter=FakeMailboxAdapter())
    send_td = MailsendToolDriver(_adapter=FakeMailsendAdapter())
    mail_td = MailToolDriver(_read_driver=read_td, _send_driver=send_td)
    return MailDriver(_tooldriver=mail_td)


class TestCompositeHybridDriver:

    def test_system_message_not_empty(self, driver: MailDriver):
        assert len(driver.get_driver_system_message()) > 0

    def test_function_description_contains_all_tools(self, driver: MailDriver):
        desc = driver.get_function_description()
        assert "list_folders" in desc
        assert "send_message" in desc

    def test_list_tools_returns_nine(self, driver: MailDriver):
        assert len(driver.list_tools()) == 9

    def test_execute_read_tool(self, driver: MailDriver):
        result = json.loads(driver.execute_tool("list_folders", {}))
        assert "INBOX" in result

    def test_execute_send_tool(self, driver: MailDriver):
        result = json.loads(driver.execute_tool("send_message", {
            "to": "a@b.c", "subject": "Hi", "body": "Hello",
        }))
        assert result["status"] == "sent"

    def test_meta_attributes(self, driver: MailDriver):
        assert driver.meta.name == "Mail MCS Driver"
        assert "standalone" in driver.meta.capabilities
        assert len(driver.meta.bindings) == 2
