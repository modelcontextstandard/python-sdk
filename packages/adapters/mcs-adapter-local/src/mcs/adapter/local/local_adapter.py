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
import shutil
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Optional, Union

#: The `timeout(1)` convention: 124 means "killed because time ran out".
_TIMEOUT_EXIT_CODE = 124


@dataclass
class ExecResult:
    """What one command measurably produced (structurally ExecutorPort's)."""

    exit_code: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class ShellSpec:
    """A statement about a shell this machine has -- argv, name, and a note.

    The three travel together on purpose: the *name* becomes the tool's name
    (a `bash` tool with PowerShell behind it would lure the model into POSIX
    syntax -- the trained name beats a description line), the *note* becomes
    the sentence in the tool description that tells the model which syntax
    applies, and the *argv* is how the adapter actually spawns it.
    """

    argv: tuple[str, ...]
    name: str        # "bash" | "powershell" | "cmd" -- the tool name to advertise
    note: str        # e.g. "Git Bash (POSIX sh)" -- shown to the model


#: Where Git for Windows puts bash.exe when installed with defaults -- the same
#: well-known path pi checks (its docs/windows.md) and Claude Code requires.
_GIT_BASH_DEFAULT = r"C:\Program Files\Git\bin\bash.exe"

#: pi's measured PowerShell start flags (-NoProfile -NonInteractive
#: -ExecutionPolicy Bypass); admin-enforced policies still win, which is fine.
_POWERSHELL_FLAGS = ("-NoProfile", "-NonInteractive",
                     "-ExecutionPolicy", "Bypass", "-Command")


def find_shell(
    override: Optional[str] = None,
    *,
    _which: Callable[[str], Optional[str]] = shutil.which,
    _exists: Callable[[str], bool] = os.path.exists,
) -> ShellSpec:
    """State which shell this machine offers, best first -- never a guess.

    The order is the measured practice of the harnesses (Claude Code, pi,
    Gemini CLI): a POSIX bash is strongly preferred because it is the syntax
    models are trained deepest on; PowerShell is the declared fallback (the
    Gemini model: platform shell, said out loud); ``cmd.exe`` is the honest
    last resort that no harness *chooses* but every Windows box has.

    1. *override* -- the caller's explicit path (their settings, their env
       variable; this function reads none itself).
    2. Git Bash at its default install path (the well-known location).
    3. ``bash`` on PATH (Cygwin, MSYS2, WSL, any Unix).
    4. ``pwsh`` (PowerShell 7+), then ``powershell`` (Windows PowerShell 5.1).
    5. ``COMSPEC`` -- cmd.exe.

    This is detection as a *choice*: the client calls it visibly and hands the
    result to :class:`LocalAdapter`; nothing here runs on silence.
    """
    if override:
        return ShellSpec((override, "-c"), "bash", f"{override} (POSIX sh)")
    if os.name == "nt" and _exists(_GIT_BASH_DEFAULT):
        return ShellSpec((_GIT_BASH_DEFAULT, "-c"), "bash", "Git Bash (POSIX sh)")
    if bash := _which("bash"):
        return ShellSpec((bash, "-c"), "bash", "bash (POSIX)")
    if pwsh := _which("pwsh"):
        return ShellSpec((pwsh, *_POWERSHELL_FLAGS), "powershell",
                         "PowerShell 7+ (pwsh)")
    if powershell := _which("powershell"):
        return ShellSpec((powershell, *_POWERSHELL_FLAGS), "powershell",
                         "Windows PowerShell 5.1")
    if os.name == "nt":
        return ShellSpec((os.environ.get("COMSPEC", "cmd.exe"), "/c"), "cmd",
                         "cmd.exe")
    return ShellSpec(("/bin/sh", "-c"), "bash", "/bin/sh (POSIX)")


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
        How a command string becomes a process. A :class:`ShellSpec` (from
        :func:`find_shell`) is the recommended form -- it carries the tool
        name and syntax note along, so the driver can advertise the shell
        truthfully. A plain list like ``["bash", "-c"]`` pins one without a
        note. ``None`` (default) uses the platform's shell (``COMSPEC``/cmd
        on Windows, ``/bin/sh`` elsewhere), which is what "run a shell
        command" honestly means on that machine -- but note that no measured
        harness *chooses* cmd; on Windows, prefer ``find_shell()``.

    Attributes
    ----------
    tool_name :
        What the shell tool should be called for this modality (``bash``,
        ``powershell``, ``cmd``). Read structurally by the driver -- the tool
        name must never contradict the syntax the shell actually speaks.
    shell_note :
        One line naming the shell for the tool description, so the model
        writes the right syntax instead of guessing from the tool name.
    """

    def __init__(
        self,
        *,
        cwd: Optional[str] = None,
        env: Optional[dict[str, str]] = None,
        shell: Union[ShellSpec, Sequence[str], None] = None,
    ) -> None:
        self.cwd = cwd
        self._env = {**os.environ, **env} if env else None
        if isinstance(shell, ShellSpec):
            self._shell: Optional[list[str]] = list(shell.argv)
            self.tool_name = shell.name
            self.shell_note = shell.note
        elif shell:
            self._shell = list(shell)
            # A bare argv names no syntax world -- the driver keeps its default
            # tool name, and the note states at least the binary.
            self.tool_name = None
            self.shell_note = os.path.basename(self._shell[0])
        else:
            self._shell = None
            self.tool_name = "cmd" if os.name == "nt" else "bash"
            self.shell_note = ("cmd.exe (COMSPEC)" if os.name == "nt"
                               else "/bin/sh (POSIX)")

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
