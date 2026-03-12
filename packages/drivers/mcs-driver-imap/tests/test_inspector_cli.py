"""Tests for the IMAP inspector CLI module."""

from __future__ import annotations

import argparse
from unittest.mock import patch

import pytest


class TestCLIParsing:

    def test_parses_required_args(self):
        from mcs.driver.imap.inspector import _parse_args
        with patch("sys.argv", ["prog", "--host", "imap.test.local", "--user", "me@test"]):
            args = _parse_args()
        assert args.host == "imap.test.local"
        assert args.user == "me@test"
        assert args.password is None
        assert args.port is None
        assert args.no_ssl is False
        assert args.starttls is False

    def test_parses_all_args(self):
        from mcs.driver.imap.inspector import _parse_args
        with patch("sys.argv", [
            "prog",
            "--host", "mail.corp",
            "--user", "alice",
            "--password", "s3cret",
            "--port", "143",
            "--no-ssl",
            "--starttls",
        ]):
            args = _parse_args()
        assert args.host == "mail.corp"
        assert args.user == "alice"
        assert args.password == "s3cret"
        assert args.port == 143
        assert args.no_ssl is True
        assert args.starttls is True

    def test_missing_host_exits(self):
        from mcs.driver.imap.inspector import _parse_args
        with patch("sys.argv", ["prog", "--user", "me"]):
            with pytest.raises(SystemExit):
                _parse_args()

    def test_missing_user_exits(self):
        from mcs.driver.imap.inspector import _parse_args
        with patch("sys.argv", ["prog", "--host", "imap.test"]):
            with pytest.raises(SystemExit):
                _parse_args()


class TestImportInspector:

    def test_inspector_module_importable(self):
        from mcs.driver.imap import inspector
        assert hasattr(inspector, "main")

    def test_run_inspector_available_from_mcs_inspector(self):
        from mcs.inspector import run_inspector
        assert callable(run_inspector)
