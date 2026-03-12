"""Tests for MailsendDriver (HybridDriver = DriverBase + ToolDriver delegation)."""

from __future__ import annotations

import json

import pytest

from mcs.driver.mailsend import MailsendDriver, MailsendToolDriver


class FakeMailsendAdapter:
    """Minimal adapter stub."""

    def send_message(self, *, to, subject, body, cc="", bcc="", reply_to="") -> str:
        return json.dumps({"status": "sent", "from": "test@example.com",
                           "recipients": [to], "subject": subject})

    def send_html_message(self, *, to, subject, html_body, text_body="",
                          cc="", bcc="", reply_to="") -> str:
        return json.dumps({"status": "sent", "from": "test@example.com",
                           "recipients": [to], "subject": subject})

    def check_connection(self) -> str:
        return json.dumps({"status": "ok", "server": "smtp.test", "port": 587})


@pytest.fixture()
def driver() -> MailsendDriver:
    td = MailsendToolDriver(_adapter=FakeMailsendAdapter())
    return MailsendDriver(_tooldriver=td)


class TestHybridDriver:

    def test_system_message_not_empty(self, driver: MailsendDriver):
        assert len(driver.get_driver_system_message()) > 0

    def test_function_description_contains_tool_names(self, driver: MailsendDriver):
        desc = driver.get_function_description()
        assert "send_message" in desc
        assert "check_connection" in desc

    def test_list_tools_delegates(self, driver: MailsendDriver):
        assert len(driver.list_tools()) == 3

    def test_execute_tool_delegates(self, driver: MailsendDriver):
        result = json.loads(driver.execute_tool("send_message", {
            "to": "alice@example.com", "subject": "Hi", "body": "Hello",
        }))
        assert result["status"] == "sent"

    def test_meta_attributes(self, driver: MailsendDriver):
        assert driver.meta.name == "Mailsend MCS Driver"
        assert "standalone" in driver.meta.capabilities
        assert driver.meta.bindings[0].adapter == "*"
