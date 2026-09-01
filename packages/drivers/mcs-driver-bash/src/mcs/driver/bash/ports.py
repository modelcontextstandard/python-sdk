"""The executor port -- WHERE a command runs is a modality, not part of the tool.

Measured across the current harnesses (the Anthropic bash tool spec, Claude Code,
Codex CLI, Gemini CLI, pi, OpenCode): the LLM-facing surface of a shell tool is a
*command* plus, at most, a timeout -- while sandboxing, working directories and
lifecycle live in harness policy, never in the tool schema. Codex even describes
its sandbox to the model as prose *beside* the tool, not inside it.

MCS draws the same line with its own vocabulary: the DRIVER owns the LLM
interface (one ``bash`` tool), and where the command actually runs -- this
machine, a Docker container, another host over SSH, a remote service -- is an
adapter satisfying this port. Swapping the modality never changes what the
model sees.

Deliberately absent from this port:

- **Lifecycle** (start/stop/status). Operating the machine is client business,
  or the adapter's own lazy choice -- no harness exposes infrastructure
  management to the model. The idea behind the old lifecycle tools -- an agent
  booting its workstation like an employee in the morning and shutting it down
  after -- deserves its own machine-management driver some day; it does not
  belong in the shell tool.
- **File transfer** (put/get). File access is the *filesystem driver's* concern,
  one abstraction up: that driver states exactly where the model may read and
  write, per directory, per adapter -- and a client may run several of them.
  Inside its own environment bash can touch files anyway; bounding THAT is what
  the permission gate is for, not a second file API on the shell tool.
  (Concrete adapters may still offer ``put_file``/``get_file`` as *client* API
  -- provisioning a sandbox is operation, not a tool.)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass
class ExecResult:
    """What one command measurably produced.

    ``stdout`` and ``stderr`` stay separate -- merging them is a display
    decision, and a caller diagnosing a failure needs to know which stream
    said what.
    """

    exit_code: int
    stdout: str
    stderr: str


@runtime_checkable
class ExecutorPort(Protocol):
    """Contract an execution modality must satisfy: run one command, report back.

    One method, deliberately. State between calls (working directory,
    environment) is a property of the modality -- ``docker exec`` starts fresh
    every time, an SSH channel likewise -- so the port promises none, and the
    tool tells the model to chain dependent steps with ``&&`` instead.
    """

    def exec(self, command: str, *, timeout: int = 30) -> ExecResult:
        """Execute *command*, return its exit code and both streams."""
        ...
