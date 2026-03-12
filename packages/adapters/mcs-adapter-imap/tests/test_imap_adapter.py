"""Tests for ImapAdapter -- uses a fake IMAP server stub."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from mcs.adapter.imap import ImapAdapter


@pytest.fixture()
def adapter() -> ImapAdapter:
    return ImapAdapter(host="imap.test.local", user="test@test.local", password="secret")


class _FakeIMAP4:
    """Minimal stand-in for imaplib.IMAP4_SSL."""

    def login(self, user, password):
        return ("OK", [b"LOGIN completed"])

    def logout(self):
        return ("BYE", [b"Logging out"])

    def list(self):
        return ("OK", [
            b'(\\HasNoChildren) "/" "INBOX"',
            b'(\\HasNoChildren) "/" "Sent"',
            b'(\\HasNoChildren) "/" "Drafts"',
        ])

    def select(self, folder, readonly=False):
        return ("OK", [b"3"])

    def uid(self, command, *args):
        if command == "search":
            return ("OK", [b"1 2 3"])
        if command == "fetch":
            uid_str = args[0]
            header = (
                b"Subject: Test Mail\r\n"
                b"From: sender@test.local\r\n"
                b"To: test@test.local\r\n"
                b"Date: Mon, 03 Mar 2026 10:00:00 +0000\r\n"
                b"\r\n"
            )
            if "RFC822" in args[1]:
                body = header + b"Hello World"
                return ("OK", [
                    (f"{uid_str} (FLAGS (\\Seen) RFC822 {{123}})".encode(), body),
                ])
            else:
                return ("OK", [
                    (f"{uid_str} (FLAGS (\\Seen) BODY[HEADER.FIELDS (SUBJECT FROM DATE)] {{80}})".encode(), header),
                ])
        if command == "copy":
            return ("OK", [b"COPY completed"])
        if command == "store":
            return ("OK", [b"STORE completed"])
        return ("OK", [])

    def expunge(self):
        return ("OK", [])

    def create(self, name):
        return ("OK", [b"CREATE completed"])


@pytest.fixture()
def fake_imap():
    return _FakeIMAP4()


class TestListFolders:

    def test_returns_folder_names(self, adapter, fake_imap):
        with patch("mcs.adapter.imap.imap_adapter.imaplib.IMAP4_SSL", return_value=fake_imap):
            result = json.loads(adapter.list_folders())
        assert "INBOX" in result
        assert "Sent" in result
        assert "Drafts" in result


class TestListMessages:

    def test_returns_message_list(self, adapter, fake_imap):
        with patch("mcs.adapter.imap.imap_adapter.imaplib.IMAP4_SSL", return_value=fake_imap):
            result = json.loads(adapter.list_messages("INBOX", limit=2))
        assert isinstance(result, list)
        assert len(result) <= 2
        if result:
            assert "uid" in result[0]
            assert "subject" in result[0]


class TestFetchMessage:

    def test_returns_full_message(self, adapter, fake_imap):
        with patch("mcs.adapter.imap.imap_adapter.imaplib.IMAP4_SSL", return_value=fake_imap):
            result = json.loads(adapter.fetch_message(uid=1))
        assert result["uid"] == 1
        assert "subject" in result
        assert "body" in result


class TestMoveMessage:

    def test_move_returns_confirmation(self, adapter, fake_imap):
        with patch("mcs.adapter.imap.imap_adapter.imaplib.IMAP4_SSL", return_value=fake_imap):
            result = json.loads(adapter.move_message(uid=1, destination="Archive"))
        assert result["moved"] == 1
        assert result["to"] == "Archive"


class TestSetFlags:

    def test_set_flags_returns_confirmation(self, adapter, fake_imap):
        with patch("mcs.adapter.imap.imap_adapter.imaplib.IMAP4_SSL", return_value=fake_imap):
            result = json.loads(adapter.set_flags(uid=1, flags="\\Seen"))
        assert result["uid"] == 1
        assert "+FLAGS" in result["action"]

    def test_remove_flags(self, adapter, fake_imap):
        with patch("mcs.adapter.imap.imap_adapter.imaplib.IMAP4_SSL", return_value=fake_imap):
            result = json.loads(adapter.set_flags(uid=1, flags="\\Seen", remove=True))
        assert "-FLAGS" in result["action"]


class TestCreateFolder:

    def test_create_folder_returns_name(self, adapter, fake_imap):
        with patch("mcs.adapter.imap.imap_adapter.imaplib.IMAP4_SSL", return_value=fake_imap):
            result = json.loads(adapter.create_folder("Archive"))
        assert result["created"] == "Archive"


class TestSearchMessages:

    def test_search_returns_results(self, adapter, fake_imap):
        with patch("mcs.adapter.imap.imap_adapter.imaplib.IMAP4_SSL", return_value=fake_imap):
            result = json.loads(adapter.search_messages('FROM "sender"', limit=5))
        assert isinstance(result, list)
