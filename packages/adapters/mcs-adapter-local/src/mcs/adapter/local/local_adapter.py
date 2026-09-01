"""Local adapter: the run-it-right-here execution modality (ExecutorPort).

**No isolation, on purpose.** Commands run as the client's own process user on
the client's own machine -- which is exactly what every coding harness does with
its bash tool, and exactly what a consent gate exists for. This adapter is
never a silent default: a client that wants an ungated local shell has to
construct one, visibly. Pair it with ``PermissionMiddleware`` unless the
environment is disposable anyway (then Docker is the better modality).

State does **not** persist between calls -- each ``exec`` is its own process,
matching the port's promise. A stable working directory and extra environment
are construction facts (`cwd=`, `env=`), not per-call state.
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Optional

#: The `timeout(1)` convention: 124 means "killed because time ran out".
_TIMEOUT_EXIT_CODE = 124


@dataclass
class ExecResult:
    """What one command measurably produced (structurally ExecutorPort's)."""

    exit_code: int
    stdout: str
    stderr: str


class LocalAdapter:
    """Execute commands on the machine the client itself runs on.

    Parameters
    ----------
    cwd :
        Working directory for every command. ``None`` inherits the process's.
    env :
        Extra environment variables, **added to** the inherited environment --
        replacing it wholesale breaks PATH on every platform in a different way.
    shell :
        How a command string becomes a process. ``None`` (default) uses the
        platform's shell (``COMSPEC``/cmd on Windows, ``/bin/sh`` elsewhere),
        which is what "run a shell command" honestly means on that machine.
        Pass e.g. ``["bash", "-c"]`` or ``["powershell", "-Command"]`` to pin
        one -- the command is then handed to it as a single argument, with no
        shell parsing by this adapter.
    """

    def __init__(
        self,
        *,
        cwd: Optional[str] = None,
        env: Optional[dict[str, str]] = None,
        shell: Optional[Sequence[str]] = None,
    ) -> None:
        self.cwd = cwd
        self._env = {**os.environ, **env} if env else None
        self._shell = list(shell) if shell else None

    def exec(self, command: str, *, timeout: int = 30) -> ExecResult:
        """Run *command*, capture both streams, translate a timeout to exit 124.

        A timeout is an *answer* (the command was killed, here is what it said
        until then), not an exception -- the model reads exit 124 plus the note
        and reacts; a raised exception would only become a less informative
        tool failure.
        """
        try:
            completed = subprocess.run(
                [*self._shell, command] if self._shell else command,
                shell=self._shell is None,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=self.cwd,
                env=self._env,
            )
        except subprocess.TimeoutExpired as exc:
            return ExecResult(
                exit_code=_TIMEOUT_EXIT_CODE,
                stdout=_as_text(exc.stdout),
                stderr=_as_text(exc.stderr)
                + f"\n[killed: exceeded the {timeout}s timeout]",
            )
        return ExecResult(
            exit_code=completed.returncode,
            stdout=completed.stdout or "",
            stderr=completed.stderr or "",
        )


def _as_text(stream: object) -> str:
    """TimeoutExpired hands back whatever was captured -- str, bytes or None."""
    if stream is None:
        return ""
    if isinstance(stream, bytes):
        return stream.decode("utf-8", errors="replace")
    return str(stream)
