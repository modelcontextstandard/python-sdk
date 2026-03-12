"""Tests for MailreadToolDriver -- uses a fake adapter (no real connection)."""

from __future__ import annotations

import json
from typing import Any

import pytest

from mcs.driver.mailread import MailreadToolDriver


class FakeMailboxAdapter:
    """Satisfies MailboxPort without touching the network."""

    def list_folders(self) -> str:
        return json.dumps(["INBOX", "Sent", "Drafts", "Spam"])

    def list_messages(self, folder: str = "INBOX", *, limit: int = 20) -> str:
        return json.dumps([
            {"uid": 42, "subject": "Hello", "from": "bob@example.com",
             "date": "Mon, 03 Mar 2026 10:00:00 +0000", "flags": "\\Seen"},
            {"uid": 43, "subject": "Meeting", "from": "alice@example.com",
             "date": "Mon, 03 Mar 2026 11:00:00 +0000", "flags": ""},
        ][:limit])

    def fetch_message(self, uid: int, folder: str = "INBOX") -> str:
        return json.dumps({
            "uid": uid, "subject": "Hello", "from": "bob@example.com",
            "to": "test@example.com", "date": "Mon, 03 Mar 2026 10:00:00 +0000",
            "body": "Hi there, how are you?", "flags": "\\Seen",
        })

    def move_message(self, uid: int, destination: str, folder: str = "INBOX") -> str:
        return json.dumps({"moved": uid, "from": folder, "to": destination})

    def set_flags(self, uid: int, flags: str, *, remove: bool = False, folder: str = "INBOX") -> str:
        action = "-FLAGS" if remove else "+FLAGS"
        return json.dumps({"uid": uid, "action": action, "flags": flags})

    def create_folder(self, name: str) -> str:
        return json.dumps({"created": name})

    def search_messages(self, criteria: str = "ALL", folder: str = "INBOX", *, limit: int = 20) -> str:
        return json.dumps([
            {"uid": 42, "subject": "Hello", "from": "bob@example.com",
             "date": "Mon, 03 Mar 2026 10:00:00 +0000"},
        ])


@pytest.fixture()
def td() -> MailreadToolDriver:
    return MailreadToolDriver(_adapter=FakeMailboxAdapter())


# ================================================================== #
#  1. Tool listing                                                     #
# ================================================================== #

class TestListTools:

    def test_returns_seven_tools(self, td: MailreadToolDriver):
        tools = td.list_tools()
        assert len(tools) == 7

    def test_every_tool_has_name_title_description(self, td: MailreadToolDriver):
        for tool in td.list_tools():
            assert tool.name, "Tool name must not be empty"
            assert tool.title, "Tool title must not be empty"
            assert tool.description, "Tool description must not be empty"

    def test_tool_names(self, td: MailreadToolDriver):
        names = {t.name for t in td.list_tools()}
        expected = {
            "list_folders", "list_messages", "fetch_message",
            "search_messages", "move_message", "set_flags", "create_folder",
        }
        assert names == expected


# ================================================================== #
#  2. Tool execution                                                   #
# ================================================================== #

class TestExecuteTool:

    def test_list_folders(self, td: MailreadToolDriver):
        result = json.loads(td.execute_tool("list_folders", {}))
        assert "INBOX" in result

    def test_list_messages(self, td: MailreadToolDriver):
        result = json.loads(td.execute_tool("list_messages", {"folder": "INBOX", "limit": 1}))
        assert isinstance(result, list)
        assert len(result) == 1

    def test_fetch_message(self, td: MailreadToolDriver):
        result = json.loads(td.execute_tool("fetch_message", {"uid": 42}))
        assert result["uid"] == 42
        assert "body" in result

    def test_search_messages(self, td: MailreadToolDriver):
        result = json.loads(td.execute_tool("search_messages", {"criteria": 'FROM "bob"'}))
        assert isinstance(result, list)

    def test_move_message(self, td: MailreadToolDriver):
        result = json.loads(td.execute_tool("move_message", {"uid": 42, "destination": "Archive"}))
        assert result["moved"] == 42

    def test_set_flags(self, td: MailreadToolDriver):
        result = json.loads(td.execute_tool("set_flags", {"uid": 42, "flags": "\\Seen"}))
        assert "+FLAGS" in result["action"]

    def test_set_flags_remove(self, td: MailreadToolDriver):
        result = json.loads(td.execute_tool("set_flags", {"uid": 42, "flags": "\\Seen", "remove": True}))
        assert "-FLAGS" in result["action"]

    def test_create_folder(self, td: MailreadToolDriver):
        result = json.loads(td.execute_tool("create_folder", {"name": "Invoices"}))
        assert result["created"] == "Invoices"

    def test_unknown_tool_raises(self, td: MailreadToolDriver):
        with pytest.raises(ValueError, match="Unknown tool"):
            td.execute_tool("nonexistent", {})


# ================================================================== #
#  3. DriverMeta                                                       #
# ================================================================== #

class TestDriverMeta:

    def test_meta_attributes(self, td: MailreadToolDriver):
        assert td.meta.name == "Mailread MCS ToolDriver"
        assert td.meta.version == "0.1.0"
        assert len(td.meta.bindings) == 1
        assert td.meta.bindings[0].capability == "mailread"
        assert td.meta.bindings[0].adapter == "*"


# ================================================================== #
#  4. Constructor                                                      #
# ================================================================== #

class TestConstructor:

    def test_unknown_adapter_raises(self):
        with pytest.raises(ValueError, match="Unknown mailread adapter"):
            MailreadToolDriver(adapter="nonexistent")

    def test_accepts_adapter_injection(self):
        td = MailreadToolDriver(_adapter=FakeMailboxAdapter())
        assert td.list_tools()
