"""LocalAdapter against the real machine -- portable commands only.

`echo`, `exit N` and `1>&2` mean the same thing in cmd.exe and /bin/sh, so the
platform-shell default is testable everywhere; anything beyond that pins the
shell to the Python interpreter (`shell=[sys.executable, "-c"]`), which is the
one binary a test run always has.
"""

from __future__ import annotations

import os
import sys

from mcs.adapter.local import LocalAdapter, ShellSpec, find_shell
from mcs.driver.bash import ExecutorPort


def _py(*, cwd=None):
    """An adapter whose 'shell' is the Python interpreter -- fully portable."""
    return LocalAdapter(shell=[sys.executable, "-c"], cwd=cwd)


class TestContract:

    def test_satisfies_the_executor_port(self):
        assert isinstance(LocalAdapter(), ExecutorPort)


class TestPlatformShell:
    """The three commands every platform shell agrees on."""

    def test_echo_reaches_stdout(self):
        r = LocalAdapter().exec("echo hi")
        assert r.exit_code == 0
        assert "hi" in r.stdout

    def test_exit_code_is_reported(self):
        assert LocalAdapter().exec("exit 3").exit_code == 3

    def test_stderr_stays_separate(self):
        r = LocalAdapter().exec("echo err 1>&2")
        assert "err" in r.stderr
        assert "err" not in r.stdout


class TestPinnedShell:

    def test_command_is_handed_over_unparsed(self):
        r = _py().exec("print('quotes \"stay\" intact')")
        assert r.exit_code == 0
        assert 'quotes "stay" intact' in r.stdout

    def test_cwd_is_a_construction_fact(self, tmp_path):
        r = _py(cwd=str(tmp_path)).exec("import os; print(os.getcwd())")
        assert str(tmp_path) in r.stdout

    def test_env_adds_to_the_inherited_environment(self):
        adapter = LocalAdapter(shell=[sys.executable, "-c"],
                               env={"MCS_TEST_MARKER": "42"})
        r = adapter.exec("import os; print(os.environ['MCS_TEST_MARKER'])")
        assert "42" in r.stdout


class TestFindShell:
    """The measured cascade: bash strongly preferred, PowerShell the declared
    fallback, cmd the honest last resort no harness *chooses*."""

    def test_this_machine_states_a_shell(self):
        """Wherever the suite runs, the statement must be usable -- and here
        (POSIX, or Windows with Git installed) that means bash."""
        spec = find_shell()
        assert spec.name == "bash"
        r = LocalAdapter(shell=spec).exec("echo via-found-shell")
        assert r.exit_code == 0 and "via-found-shell" in r.stdout

    def test_an_override_wins_and_is_trusted(self):
        spec = find_shell(r"D:\portable\git\bash.exe")
        assert spec.argv[0] == r"D:\portable\git\bash.exe"
        assert spec.name == "bash"

    def test_without_bash_powershell_is_the_declared_fallback(self):
        spec = find_shell(_which=lambda n: "pwsh.exe" if n == "pwsh" else None,
                          _exists=lambda p: False)
        assert spec.name == "powershell"
        assert "pwsh" in spec.note
        assert "-NoProfile" in spec.argv          # pi's measured start flags

    def test_a_bare_machine_still_answers(self):
        spec = find_shell(_which=lambda n: None, _exists=lambda p: False)
        # On Windows that is cmd -- the last resort no harness chooses; on
        # POSIX /bin/sh always exists and speaks the bash tool's syntax.
        assert spec.name == ("cmd" if os.name == "nt" else "bash")


class TestModalityIdentity:
    """tool_name and shell_note are construction facts the driver reads."""

    def test_a_shellspec_names_the_modality(self):
        adapter = LocalAdapter(shell=ShellSpec(("pwsh", "-Command"),
                                               "powershell", "PowerShell 7+"))
        assert adapter.tool_name == "powershell"
        assert adapter.shell_note == "PowerShell 7+"

    def test_the_platform_default_is_named_honestly(self):
        adapter = LocalAdapter()
        assert adapter.tool_name == ("cmd" if os.name == "nt" else "bash")
        assert adapter.shell_note

    def test_a_bare_argv_names_no_syntax_world(self):
        """The client pinned a binary without a ShellSpec: the note states at
        least the binary, but no tool name is claimed."""
        adapter = _py()
        assert adapter.tool_name is None
        assert "python" in adapter.shell_note.lower()


class TestTimeout:

    def test_a_timeout_is_an_answer_not_an_exception(self):
        """exit 124 (the timeout(1) convention) plus a note -- the model reads
        and reacts; an exception would only become a mute tool failure."""
        r = _py().exec("import time; time.sleep(30)", timeout=1)
        assert r.exit_code == 124
        assert "timeout" in r.stderr
