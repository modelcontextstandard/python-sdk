"""SSH adapter implementing the SandboxPort protocol.

Turns any reachable Linux server (Hetzner VPS, Coolify host, Raspberry Pi,
cloud VM, …) into a sandbox environment via SSH + SFTP.  No Docker required
on the target — just an SSH server.

The adapter manages a persistent SSH connection and uses paramiko for
command execution and file transfer.
"""

from __future__ import annotations

import io
import logging
import os
import posixpath
import stat
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Union

import paramiko

logger = logging.getLogger(__name__)


@dataclass
class ExecResult:
    """Result of a command execution over SSH."""

    exit_code: int
    stdout: str
    stderr: str


class SSHAdapter:
    """Adapter that runs sandbox operations on a remote host via SSH.

    Parameters
    ----------
    host : str
        Hostname or IP address of the SSH server.
    user : str
        SSH username.
    password : str | None
        Password for authentication (mutually exclusive with *key_path*
        for simplicity, but both can be provided for fallback).
    key_path : str | None
        Path to a private key file (e.g. ``~/.ssh/id_ed25519``).
    key_passphrase : str | None
        Passphrase for the private key (if encrypted).
    port : int
        SSH port (default 22).
    working_dir : str
        Default working directory on the remote host.  Created on
        ``start()`` if it doesn't exist.
    connect_timeout : int
        Connection timeout in seconds.
    known_hosts_policy : str
        How to handle unknown host keys:
        ``"reject"`` (default, secure), ``"auto_add"`` (for testing),
        or ``"warn"`` (log but accept).
    """

    def __init__(
        self,
        *,
        host: str,
        user: str,
        password: Optional[str] = None,
        key_path: Optional[str] = None,
        key_passphrase: Optional[str] = None,
        port: int = 22,
        working_dir: str = "/workspace",
        connect_timeout: int = 10,
        known_hosts_policy: str = "reject",
    ) -> None:
        self._host = host
        self._user = user
        self._password = password
        self._key_path = key_path
        self._key_passphrase = key_passphrase
        self._port = port
        self._working_dir = working_dir
        self._connect_timeout = connect_timeout
        self._known_hosts_policy = known_hosts_policy

        self._client: Optional[paramiko.SSHClient] = None
        self._sftp: Optional[paramiko.SFTPClient] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> Dict[str, Any]:
        """Open an SSH connection and ensure the working directory exists.

        Idempotent — if already connected, validates the connection and
        returns the current status.
        """
        if self._client is not None and self._is_connected():
            logger.info("SSH connection to %s already active", self._host)
            return self.status()

        client = paramiko.SSHClient()

        # Host key policy
        if self._known_hosts_policy == "auto_add":
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        elif self._known_hosts_policy == "warn":
            client.set_missing_host_key_policy(paramiko.WarningPolicy())
        else:
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
            # Load system known hosts
            known_hosts = os.path.expanduser("~/.ssh/known_hosts")
            if os.path.exists(known_hosts):
                client.load_host_keys(known_hosts)

        connect_kwargs: Dict[str, Any] = {
            "hostname": self._host,
            "port": self._port,
            "username": self._user,
            "timeout": self._connect_timeout,
        }

        if self._key_path:
            expanded = os.path.expanduser(self._key_path)
            pkey = paramiko.Ed25519Key.from_private_key_file(
                expanded, password=self._key_passphrase
            )
            connect_kwargs["pkey"] = pkey
        elif self._password:
            connect_kwargs["password"] = self._password

        client.connect(**connect_kwargs)
        self._client = client

        logger.info(
            "SSH connected to %s@%s:%d", self._user, self._host, self._port
        )

        # Ensure working directory exists
        self._exec_raw(f"mkdir -p {self._working_dir}")

        return self.status()

    def stop(self) -> Dict[str, Any]:
        """Close the SSH connection gracefully."""
        if self._sftp is not None:
            try:
                self._sftp.close()
            except Exception:
                pass
            self._sftp = None

        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass
            logger.info("SSH connection to %s closed", self._host)
            self._client = None

        return {"status": "stopped", "host": self._host}

    def status(self) -> Dict[str, Any]:
        """Return current connection status."""
        connected = self._is_connected()
        return {
            "running": connected,
            "host": self._host,
            "port": self._port,
            "user": self._user,
            "working_dir": self._working_dir,
            "exists": True,
        }

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def exec(self, command: str, *, timeout: int = 30) -> ExecResult:
        """Execute a shell command on the remote host.

        The command runs in the configured working directory via
        ``cd <working_dir> && <command>``.
        """
        self._ensure_connected()
        assert self._client is not None

        wrapped = f"cd {self._working_dir} && {command}"
        stdin, stdout, stderr = self._client.exec_command(
            wrapped, timeout=timeout
        )

        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        exit_code = stdout.channel.recv_exit_status()

        return ExecResult(exit_code=exit_code, stdout=out, stderr=err)

    # ------------------------------------------------------------------
    # File transfer (via SFTP)
    # ------------------------------------------------------------------

    def put_file(self, path: str, content: bytes) -> None:
        """Upload *content* to *path* on the remote host.

        Parent directories are created automatically.
        """
        self._ensure_connected()
        sftp = self._get_sftp()

        # Ensure parent directory exists
        parent = posixpath.dirname(path)
        if parent and parent != "/":
            self._exec_raw(f"mkdir -p {parent}")

        with sftp.open(path, "wb") as f:
            f.write(content)

        logger.info("Uploaded %d bytes to %s:%s", len(content), self._host, path)

    def get_file(self, path: str) -> bytes:
        """Download a file from *path* on the remote host."""
        self._ensure_connected()
        sftp = self._get_sftp()

        with sftp.open(path, "rb") as f:
            return f.read()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _is_connected(self) -> bool:
        """Check if the SSH transport is still active."""
        if self._client is None:
            return False
        transport = self._client.get_transport()
        return transport is not None and transport.is_active()

    def _ensure_connected(self) -> None:
        """Raise if not connected."""
        if not self._is_connected():
            raise RuntimeError(
                f"SSH not connected to {self._host}. Call start() first."
            )

    def _get_sftp(self) -> paramiko.SFTPClient:
        """Return (or open) an SFTP session over the existing connection."""
        assert self._client is not None
        if self._sftp is None or self._sftp.get_channel() is None:
            self._sftp = self._client.open_sftp()
        return self._sftp

    def _exec_raw(self, command: str) -> str:
        """Execute a command without cd-wrapping.  For internal use."""
        assert self._client is not None
        _stdin, stdout, _stderr = self._client.exec_command(command, timeout=10)
        return stdout.read().decode("utf-8", errors="replace")
