"""LocalAdapter against the real machine -- portable commands only.

`echo`, `exit N` and `1>&2` mean the same thing in cmd.exe and /bin/sh, so the
platform-shell default is testable everywhere; anything beyond that pins the
shell to the Python interpreter (`shell=[sys.executable, "-c"]`), which is the
one binary a test run always has.
"""

from __future__ import annotations

import sys

from mcs.adapter.local import LocalAdapter
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


class TestTimeout:

    def test_a_timeout_is_an_answer_not_an_exception(self):
        """exit 124 (the timeout(1) convention) plus a note -- the model reads
        and reacts; an exception would only become a mute tool failure."""
        r = _py().exec("import time; time.sleep(30)", timeout=1)
        assert r.exit_code == 124
        assert "timeout" in r.stderr
