"""Sandbox port — the backend-agnostic interface for isolated compute.

Any adapter that satisfies this protocol can be used as a sandbox backend:
Docker, SSH, E2B, Coolify, a local subprocess, or anything else that can
execute commands and transfer files.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Protocol, runtime_checkable


@dataclass
class ExecResult:
    """Result of a command execution inside the sandbox."""

    exit_code: int
    stdout: str
    stderr: str


@runtime_checkable
class SandboxPort(Protocol):
    """Contract that every sandbox backend must satisfy.

    Three capabilities — execute, upload, download — plus lifecycle.
    """

    def start(self) -> Dict[str, Any]:
        """Start or resume the sandbox.  Returns status metadata."""
        ...

    def stop(self) -> Dict[str, Any]:
        """Stop the sandbox (preserving state).  Returns status metadata."""
        ...

    def status(self) -> Dict[str, Any]:
        """Return current sandbox status including ``running`` boolean."""
        ...

    def exec(self, command: str, *, timeout: int = 30) -> ExecResult:
        """Execute a shell command and return stdout/stderr/exit_code."""
        ...

    def put_file(self, path: str, content: bytes) -> None:
        """Upload *content* to *path* inside the sandbox."""
        ...

    def get_file(self, path: str) -> bytes:
        """Download the file at *path* from the sandbox."""
        ...
