"""Unit tests for the SSHAdapter with mocked paramiko.

No SSH server or Docker required — pure mock-based testing.
"""

from __future__ import annotations

import io
from unittest.mock import MagicMock, patch, call

import pytest

from mcs.adapter.ssh.ssh_adapter import SSHAdapter, ExecResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_exec_command(command: str, timeout: int = 30):
    """Return mock stdin/stdout/stderr with a successful result."""
    stdin = MagicMock()
    stdout = MagicMock()
    stderr = MagicMock()
    stdout.read.return_value = b"output\n"
    stderr.read.return_value = b""
    stdout.channel.recv_exit_status.return_value = 0
    return stdin, stdout, stderr


def _mock_exec_command_fail(command: str, timeout: int = 30):
    """Return mock stdin/stdout/stderr with a failed result."""
    stdin = MagicMock()
    stdout = MagicMock()
    stderr = MagicMock()
    stdout.read.return_value = b""
    stderr.read.return_value = b"error message\n"
    stdout.channel.recv_exit_status.return_value = 1
    return stdin, stdout, stderr


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_paramiko():
    """Patch paramiko.SSHClient and return the mock client instance."""
    with patch("mcs.adapter.ssh.ssh_adapter.paramiko") as mock_mod:
        client_instance = MagicMock()
        mock_mod.SSHClient.return_value = client_instance

        # Transport is active after connect
        transport = MagicMock()
        transport.is_active.return_value = True
        client_instance.get_transport.return_value = transport

        # Default exec_command behavior
        client_instance.exec_command.side_effect = _mock_exec_command

        # SFTP mock
        sftp = MagicMock()
        client_instance.open_sftp.return_value = sftp
        sftp.get_channel.return_value = MagicMock()

        # Make policy classes available
        mock_mod.AutoAddPolicy = MagicMock
        mock_mod.WarningPolicy = MagicMock
        mock_mod.RejectPolicy = MagicMock
        mock_mod.Ed25519Key = MagicMock()

        yield {
            "module": mock_mod,
            "client": client_instance,
            "transport": transport,
            "sftp": sftp,
        }


@pytest.fixture
def adapter(mock_paramiko) -> SSHAdapter:
    """Create an adapter with password auth."""
    return SSHAdapter(
        host="10.0.0.1",
        user="agent",
        password="secret",
        known_hosts_policy="auto_add",
    )


# ---------------------------------------------------------------------------
# Constructor
# ---------------------------------------------------------------------------


class TestConstructor:
    def test_default_values(self, mock_paramiko):
        a = SSHAdapter(host="server", user="root", password="pw")
        assert a._host == "server"
        assert a._port == 22
        assert a._working_dir == "/workspace"
        assert a._known_hosts_policy == "reject"

    def test_custom_values(self, mock_paramiko):
        a = SSHAdapter(
            host="my.server.com",
            user="deploy",
            key_path="~/.ssh/id_ed25519",
            port=2222,
            working_dir="/home/deploy/sandbox",
            known_hosts_policy="warn",
        )
        assert a._host == "my.server.com"
        assert a._port == 2222
        assert a._working_dir == "/home/deploy/sandbox"


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


class TestLifecycle:
    def test_start_connects(self, adapter, mock_paramiko):
        result = adapter.start()
        mock_paramiko["client"].connect.assert_called_once()
        assert result["running"] is True
        assert result["host"] == "10.0.0.1"

    def test_start_creates_working_dir(self, adapter, mock_paramiko):
        adapter.start()
        # Should have called mkdir -p /workspace
        calls = mock_paramiko["client"].exec_command.call_args_list
        mkdir_calls = [c for c in calls if "mkdir -p" in str(c)]
        assert len(mkdir_calls) >= 1

    def test_start_idempotent(self, adapter, mock_paramiko):
        adapter.start()
        adapter.start()
        # connect called only once
        mock_paramiko["client"].connect.assert_called_once()

    def test_stop_closes(self, adapter, mock_paramiko):
        adapter.start()
        result = adapter.stop()
        mock_paramiko["client"].close.assert_called_once()
        assert result["status"] == "stopped"

    def test_status_when_disconnected(self, mock_paramiko):
        a = SSHAdapter(host="x", user="y", password="z", known_hosts_policy="auto_add")
        # Not connected yet
        result = a.status()
        assert result["running"] is False


# ---------------------------------------------------------------------------
# Exec
# ---------------------------------------------------------------------------


class TestExec:
    def test_exec_success(self, adapter, mock_paramiko):
        adapter.start()
        result = adapter.exec("echo hello")
        assert result.exit_code == 0
        assert result.stdout == "output\n"

    def test_exec_wraps_with_cd(self, adapter, mock_paramiko):
        adapter.start()
        adapter.exec("ls -la")
        # The most recent exec_command call should include cd
        last_call = mock_paramiko["client"].exec_command.call_args_list[-1]
        command_arg = last_call[0][0]
        assert command_arg.startswith("cd /workspace && ")
        assert "ls -la" in command_arg

    def test_exec_failure(self, adapter, mock_paramiko):
        adapter.start()
        mock_paramiko["client"].exec_command.side_effect = _mock_exec_command_fail
        result = adapter.exec("bad command")
        assert result.exit_code == 1
        assert "error message" in result.stderr

    def test_exec_requires_connection(self, mock_paramiko):
        a = SSHAdapter(host="x", user="y", password="z", known_hosts_policy="auto_add")
        with pytest.raises(RuntimeError, match="not connected"):
            a.exec("echo hi")


# ---------------------------------------------------------------------------
# File transfer
# ---------------------------------------------------------------------------


class TestFileTransfer:
    def test_put_file(self, adapter, mock_paramiko):
        adapter.start()

        mock_file = MagicMock()
        mock_paramiko["sftp"].open.return_value.__enter__ = lambda s: mock_file
        mock_paramiko["sftp"].open.return_value.__exit__ = MagicMock(return_value=False)

        adapter.put_file("/workspace/test.txt", b"hello world")

        mock_paramiko["sftp"].open.assert_called_once_with("/workspace/test.txt", "wb")
        mock_file.write.assert_called_once_with(b"hello world")

    def test_get_file(self, adapter, mock_paramiko):
        adapter.start()

        mock_file = MagicMock()
        mock_file.read.return_value = b"file contents"
        mock_paramiko["sftp"].open.return_value.__enter__ = lambda s: mock_file
        mock_paramiko["sftp"].open.return_value.__exit__ = MagicMock(return_value=False)

        data = adapter.get_file("/workspace/test.txt")

        mock_paramiko["sftp"].open.assert_called_once_with("/workspace/test.txt", "rb")
        assert data == b"file contents"

    def test_put_file_creates_parent_dirs(self, adapter, mock_paramiko):
        adapter.start()

        mock_file = MagicMock()
        mock_paramiko["sftp"].open.return_value.__enter__ = lambda s: mock_file
        mock_paramiko["sftp"].open.return_value.__exit__ = MagicMock(return_value=False)

        adapter.put_file("/workspace/deep/nested/file.txt", b"data")

        # Should have called mkdir -p for the parent
        calls = mock_paramiko["client"].exec_command.call_args_list
        mkdir_calls = [c for c in calls if "mkdir -p /workspace/deep/nested" in str(c)]
        assert len(mkdir_calls) >= 1

    def test_file_ops_require_connection(self, mock_paramiko):
        a = SSHAdapter(host="x", user="y", password="z", known_hosts_policy="auto_add")
        with pytest.raises(RuntimeError):
            a.put_file("/tmp/x", b"data")
        with pytest.raises(RuntimeError):
            a.get_file("/tmp/x")


# ---------------------------------------------------------------------------
# Auth modes
# ---------------------------------------------------------------------------


class TestAuth:
    def test_password_auth(self, mock_paramiko):
        a = SSHAdapter(
            host="server", user="root", password="s3cret",
            known_hosts_policy="auto_add",
        )
        a.start()
        connect_kwargs = mock_paramiko["client"].connect.call_args
        assert connect_kwargs[1]["password"] == "s3cret"

    def test_key_auth(self, mock_paramiko):
        mock_paramiko["module"].Ed25519Key.from_private_key_file.return_value = "fake_key"
        a = SSHAdapter(
            host="server", user="deploy",
            key_path="~/.ssh/id_ed25519",
            known_hosts_policy="auto_add",
        )
        a.start()
        connect_kwargs = mock_paramiko["client"].connect.call_args
        assert connect_kwargs[1]["pkey"] == "fake_key"
