"""BashToolDriver against a fake executor -- no shell, no Docker, deterministic.

What these tests pin down is the LLM interface: the measured harness-convergent
signature (command + optional timeout + optional description), the absence of
lifecycle and file tools, the constructor-held timeout policy, and the
self-describing truncation.
"""

from __future__ import annotations

import pytest

from mcs.driver.bash import BashDriver, BashToolDriver, ExecResult, ExecutorPort


class FakeExecutor:
    """Records what it was asked to run; answers with a canned result."""

    def __init__(self, result: ExecResult | None = None):
        self.calls: list[tuple[str, int]] = []
        self.result = result or ExecResult(exit_code=0, stdout="ok", stderr="")

    def exec(self, command: str, *, timeout: int = 30) -> ExecResult:
        self.calls.append((command, timeout))
        return self.result


class TestContract:

    def test_the_fake_satisfies_the_port(self):
        assert isinstance(FakeExecutor(), ExecutorPort)

    def test_an_executor_is_required_not_defaulted(self):
        """An ungated shell must be a choice someone made -- never what happens
        silently when a client passes nothing."""
        with pytest.raises(TypeError):
            BashToolDriver()                         # type: ignore[call-arg]
        with pytest.raises(ValueError, match="executor"):
            BashToolDriver(None)                     # type: ignore[arg-type]
        with pytest.raises(ValueError, match="executor"):
            BashDriver()

    def test_unknown_tool_raises(self):
        with pytest.raises(ValueError, match="Unknown tool"):
            BashToolDriver(FakeExecutor()).execute_tool("shell_exec", {})


class TestToolSurface:
    """The measured harness convergence: one `bash` tool, nothing else."""

    def test_exactly_one_tool_named_bash(self):
        [tool] = BashToolDriver(FakeExecutor()).list_tools()
        assert tool.name == "bash"

    def test_no_lifecycle_and_no_file_tools(self):
        """No harness exposes infrastructure management or a file API on its
        shell tool -- operating the machine is client business, file access is
        the filesystem driver's concern, one abstraction up."""
        names = [t.name for t in BashToolDriver(FakeExecutor()).list_tools()]
        assert names == ["bash"]

    def test_description_is_offered_but_never_required(self):
        """The OpenCode lesson, measured: a required description makes every
        call fail the moment the model omits it."""
        [tool] = BashToolDriver(FakeExecutor()).list_tools()
        by_name = {p.name: p for p in tool.parameters}
        assert by_name["command"].required is True
        assert by_name["timeout"].required is False
        assert by_name["description"].required is False


class TestExecution:

    def test_command_reaches_the_executor_and_the_result_comes_back(self):
        fake = FakeExecutor(ExecResult(exit_code=2, stdout="out", stderr="err"))
        result = BashToolDriver(fake).execute_tool("bash", {"command": "ls -la"})
        assert fake.calls[0][0] == "ls -la"
        assert result == {"exit_code": 2, "stdout": "out", "stderr": "err"}

    def test_description_is_for_the_gate_not_the_execution(self):
        """Execution must not depend on prose -- the parameter exists for the
        human approving the call and is deliberately not interpreted."""
        fake = FakeExecutor()
        BashToolDriver(fake).execute_tool(
            "bash", {"command": "ls", "description": "list the workdir"})
        assert fake.calls == [("ls", 30)]


class TestTimeoutPolicy:
    """The Claude Code pattern: the model asks, the constructor bounds."""

    def test_default_applies_when_the_call_names_none(self):
        fake = FakeExecutor()
        BashToolDriver(fake, default_timeout=45).execute_tool(
            "bash", {"command": "x"})
        assert fake.calls[0][1] == 45

    def test_a_requested_timeout_is_passed_through(self):
        fake = FakeExecutor()
        BashToolDriver(fake).execute_tool("bash", {"command": "x", "timeout": 120})
        assert fake.calls[0][1] == 120

    def test_the_ceiling_caps_rather_than_refuses(self):
        """The model asked for "long"; long it gets -- up to the harness bound."""
        fake = FakeExecutor()
        BashToolDriver(fake, max_timeout=300).execute_tool(
            "bash", {"command": "x", "timeout": 99_999})
        assert fake.calls[0][1] == 300


class TestTruncation:
    """The webfetch pattern on shell output: silent clipping sends agents into
    retry loops (measured in the field), so the result describes the cut."""

    def test_long_output_is_clipped_and_says_so(self):
        fake = FakeExecutor(ExecResult(0, "x" * 50_000, ""))
        result = BashToolDriver(fake, max_output_chars=1_000).execute_tool(
            "bash", {"command": "cat big"})
        assert len(result["stdout"]) == 1_000
        assert result["truncated"] is True
        assert "50,000" in result["note"]           # the full size is named

    def test_each_stream_has_its_own_budget(self):
        fake = FakeExecutor(ExecResult(1, "short", "e" * 5_000))
        result = BashToolDriver(fake, max_output_chars=1_000).execute_tool(
            "bash", {"command": "x"})
        assert result["stdout"] == "short"
        assert len(result["stderr"]) == 1_000
        assert result["truncated"] is True

    def test_short_output_carries_no_truncation_noise(self):
        result = BashToolDriver(FakeExecutor()).execute_tool(
            "bash", {"command": "x"})
        assert "truncated" not in result and "note" not in result


class TestModalityIdentity:
    """The tool must never claim a syntax world the shell does not speak: the
    modality names itself (tool_name/shell_note, read structurally -- the
    LLMPort.model pattern), and the surface follows."""

    class PowershellExecutor(FakeExecutor):
        tool_name = "powershell"
        shell_note = "Windows PowerShell 5.1"

    class NotedExecutor(FakeExecutor):
        shell_note = "the container's /bin/sh (POSIX)"   # a name-less statement

    def test_the_tool_is_named_after_the_modality(self):
        driver = BashToolDriver(self.PowershellExecutor())
        [tool] = driver.list_tools()
        assert tool.name == "powershell"
        assert "Windows PowerShell 5.1" in tool.description
        assert driver.execute_tool("powershell", {"command": "dir"})["exit_code"] == 0

    def test_the_old_name_is_gone_with_the_modality(self):
        """One surface, not two: a powershell modality answers no `bash`."""
        with pytest.raises(ValueError, match="Unknown tool"):
            BashToolDriver(self.PowershellExecutor()).execute_tool(
                "bash", {"command": "x"})

    def test_a_note_without_a_name_keeps_bash_and_gains_the_sentence(self):
        """The Docker/SSH case: POSIX behind the tool, so `bash` stays -- and
        the description says which /bin/sh answers."""
        [tool] = BashToolDriver(self.NotedExecutor()).list_tools()
        assert tool.name == "bash"
        assert "the container's /bin/sh (POSIX)" in tool.description

    def test_a_silent_modality_keeps_the_plain_surface(self):
        [tool] = BashToolDriver(FakeExecutor()).list_tools()
        assert tool.name == "bash"
        assert "Commands run in" not in tool.description


class TestDriverWrapper:

    def test_the_hybrid_driver_delegates(self):
        fake = FakeExecutor()
        driver = BashDriver(fake)
        assert [t.name for t in driver.list_tools()] == ["bash"]
        result = driver.execute_tool("bash", {"command": "echo hi"})
        assert result["exit_code"] == 0
