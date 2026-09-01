"""Bash ToolDriver -- one ``bash`` tool, the way every harness spells it.

The signature is the measured convergence of Claude Code, Codex CLI, Gemini CLI,
pi and OpenCode: ``command`` (required), ``timeout`` (optional, with a default
and a ceiling held by the constructor -- the Claude Code pattern), and an
optional ``description`` for whoever approves the call. pi proves the minimal
form carries a full coding agent; everything beyond it (workdir, background,
restart) is a harness choice, added here only when a real need is measured.

Two lessons from the field are built in:

- ``description`` is **optional**. OpenCode made it required and every call
  fails when the model omits it -- a measured bug, not a style question.
- Long output is **truncated self-describingly** (flag + totals + how to get
  the rest), because silent clipping sends agents into retry loops -- the same
  pattern webfetch established for pages.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List

from mcs.driver.core.mcs_driver_interface import DriverBinding, DriverMeta
from mcs.driver.core.mcs_tool_driver_interface import (
    MCSToolDriver,
    Tool,
    ToolParameter,
)

from .ports import ExecutorPort

logger = logging.getLogger(__name__)

#: Seconds a command may run when the call names no timeout.
DEFAULT_TIMEOUT = 30
#: Ceiling on what a call may request -- the model asks, the harness bounds.
DEFAULT_MAX_TIMEOUT = 600
#: Per-stream output cap. Beyond it the result says so and names the totals,
#: so the model filters (grep, head, tail) instead of guessing what it missed.
DEFAULT_MAX_OUTPUT_CHARS = 30_000


@dataclass(frozen=True)
class _BashToolDriverMeta(DriverMeta):
    id: str = "b2c3d4e5-ba01-4000-9000-bash00000001"
    name: str = "Bash MCS ToolDriver"
    version: str = "0.2.0"
    bindings: tuple = (
        DriverBinding(capability="bash", adapter="*", spec_format="Custom"),
    )
    supported_llms: None = None
    capabilities: tuple = ("orchestratable",)


class BashToolDriver(MCSToolDriver):
    """ToolDriver exposing one ``bash`` tool over an injected executor.

    Parameters
    ----------
    executor :
        The execution modality -- **injected, never constructed here, no silent
        default**: an ungated local subprocess must be a choice someone made.
        Local machine, Docker, SSH, remote service -- the model sees the same
        tool either way; see :class:`~mcs.driver.bash.ExecutorPort`. The
        executor must be operational: starting a container or opening a
        connection is client business (or the adapter's own lazy choice), not
        the model's -- there are deliberately no lifecycle tools.
    default_timeout :
        Seconds applied when a call names none.
    max_timeout :
        Ceiling on what a call may request. Requests beyond it are capped, not
        refused -- the model asked for "long", and long it gets.
    max_output_chars :
        Per-stream cap on what a result carries back into the conversation.
    """

    meta: DriverMeta = _BashToolDriverMeta()

    def __init__(
        self,
        executor: ExecutorPort,
        *,
        default_timeout: int = DEFAULT_TIMEOUT,
        max_timeout: int = DEFAULT_MAX_TIMEOUT,
        max_output_chars: int = DEFAULT_MAX_OUTPUT_CHARS,
    ) -> None:
        if executor is None:
            raise ValueError(
                "BashToolDriver needs an executor -- where commands run is a "
                "choice the client makes (LocalAdapter, DockerAdapter, "
                "SSHAdapter, ...), never a silent default."
            )
        self._executor = executor
        self._default_timeout = default_timeout
        self._max_timeout = max_timeout
        self._max_output_chars = max_output_chars
        # The modality may name itself -- read structurally, the LLMPort.model
        # pattern. A `bash` tool with PowerShell behind it would lure the model
        # into POSIX syntax: the trained tool name beats a description line, so
        # the name must never contradict what the shell actually speaks.
        self._tool_name: str = getattr(executor, "tool_name", None) or "bash"
        self._shell_note: str | None = getattr(executor, "shell_note", None)

    # -- MCSToolDriver interface ----------------------------------------------

    def list_tools(self) -> List[Tool]:
        return [
            Tool(
                name=self._tool_name,
                description=(
                    "Execute a shell command and return exit_code, stdout and "
                    "stderr. "
                    + (f"Commands run in {self._shell_note} -- use its "
                       f"syntax. " if self._shell_note else "")
                    + "Each call is independent -- state such as the working "
                    "directory or environment variables does not reliably "
                    "persist between calls, so run dependent steps as one "
                    "command. Output beyond a limit is truncated and the "
                    "result says so; re-run with a filter to see specific "
                    "parts."
                ),
                parameters=[
                    ToolParameter(
                        name="command",
                        description="The shell command to execute.",
                        required=True,
                        schema={"type": "string"},
                    ),
                    ToolParameter(
                        name="timeout",
                        description=(
                            f"Maximum execution time in seconds (default "
                            f"{self._default_timeout}, capped at "
                            f"{self._max_timeout})."
                        ),
                        required=False,
                        schema={"type": "integer",
                                "default": self._default_timeout},
                    ),
                    ToolParameter(
                        name="description",
                        description=(
                            "One short line: what this command does and why. "
                            "Shown to whoever approves the call."
                        ),
                        required=False,
                        schema={"type": "string"},
                    ),
                ],
            )
        ]

    def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        if tool_name != self._tool_name:
            raise ValueError(f"Unknown tool: {tool_name}")

        command = arguments["command"]
        # `description` is deliberately not read here: it exists for the human
        # in the loop -- a permission middleware shows it with the pending call
        # -- and execution must not depend on prose.
        requested = arguments.get("timeout") or self._default_timeout
        timeout = max(1, min(int(requested), self._max_timeout))

        result = self._executor.exec(command, timeout=timeout)
        logger.info("bash [exit=%d]: %s", result.exit_code, command[:80])

        out: Dict[str, Any] = {
            "exit_code": result.exit_code,
            "stdout": result.stdout[: self._max_output_chars],
            "stderr": result.stderr[: self._max_output_chars],
        }
        if (len(result.stdout) > self._max_output_chars
                or len(result.stderr) > self._max_output_chars):
            out["truncated"] = True
            out["note"] = (
                f"Output truncated to {self._max_output_chars:,} chars per "
                f"stream (full: stdout {len(result.stdout):,}, stderr "
                f"{len(result.stderr):,}). Re-run with a filter (grep, head, "
                f"tail) to see the rest."
            )
        return out
