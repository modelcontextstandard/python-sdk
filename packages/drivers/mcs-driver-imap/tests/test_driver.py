"""Tests for ImapDriver (HybridDriver = DriverBase + ToolDriver delegation)."""

from __future__ import annotations

import json
from typing import Any

import pytest

from mcs.driver.imap import ImapDriver, ImapToolDriver


class FakeImapAdapter:
    """Minimal adapter stub."""

    def list_folders(self) -> str:
        return json.dumps(["INBOX", "Archive"])

    def list_messages(self, folder="INBOX", *, limit=20) -> str:
        return json.dumps([{"uid": 1, "subject": "Test", "from": "a@b.c", "date": "", "flags": ""}])

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


@pytest.fixture()
def driver() -> ImapDriver:
    td = ImapToolDriver(_adapter=FakeImapAdapter())
    return ImapDriver(_tooldriver=td)


class TestHybridDriver:

    def test_system_message_not_empty(self, driver: ImapDriver):
        msg = driver.get_driver_system_message()
        assert len(msg) > 0

    def test_function_description_not_empty(self, driver: ImapDriver):
        desc = driver.get_function_description()
        assert len(desc) > 0

    def test_function_description_contains_tool_names(self, driver: ImapDriver):
        desc = driver.get_function_description()
        assert "list_folders" in desc
        assert "fetch_message" in desc

    def test_list_tools_delegates(self, driver: ImapDriver):
        tools = driver.list_tools()
        assert len(tools) == 7

    def test_execute_tool_delegates(self, driver: ImapDriver):
        result = json.loads(driver.execute_tool("list_folders", {}))
        assert "INBOX" in result

    def test_meta_attributes(self, driver: ImapDriver):
        assert driver.meta.name == "IMAP MCS Driver"
        assert "standalone" in driver.meta.capabilities
        assert "orchestratable" in driver.meta.capabilities
