"""Tests for SandboxToolDriver using a fake in-memory adapter."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from typing import Any, Dict

import pytest

from mcs.driver.sandbox.ports import ExecResult, SandboxPort
from mcs.driver.sandbox.tooldriver import SandboxToolDriver


# ---------------------------------------------------------------------------
# Fake adapter that satisfies SandboxPort without Docker
# ---------------------------------------------------------------------------


class FakeSandboxAdapter:
    """In-memory sandbox adapter for unit testing."""

    def __init__(self) -> None:
        self._running = False
        self._files: Dict[str, bytes] = {}
        self._exec_log: list[str] = []

    def start(self) -> Dict[str, Any]:
        self._running = True
        return {"running": True, "container": "fake", "working_dir": "/workspace"}

    def stop(self) -> Dict[str, Any]:
        self._running = False
        return {"status": "stopped", "container": "fake"}

    def status(self) -> Dict[str, Any]:
        return {"running": self._running, "container": "fake", "exists": True}

    def exec(self, command: str, *, timeout: int = 30) -> ExecResult:
        self._exec_log.append(command)
        if command.startswith("fail"):
            return ExecResult(exit_code=1, stdout="", stderr="command failed")
        return ExecResult(exit_code=0, stdout=f"ran: {command}", stderr="")

    def put_file(self, path: str, content: bytes) -> None:
        self._files[path] = content

    def get_file(self, path: str) -> bytes:
        if path not in self._files:
            raise FileNotFoundError(f"No such file: {path}")
        return self._files[path]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def adapter() -> FakeSandboxAdapter:
    return FakeSandboxAdapter()


@pytest.fixture
def driver(adapter: FakeSandboxAdapter) -> SandboxToolDriver:
    return SandboxToolDriver(_adapter=adapter)


# ---------------------------------------------------------------------------
# Tool visibility (dynamic list_tools)
# ---------------------------------------------------------------------------


class TestDynamicToolVisibility:
    def test_only_start_and_status_when_stopped(self, driver: SandboxToolDriver):
        tools = driver.list_tools()
        names = {t.name for t in tools}
        assert names == {"sandbox_start", "sandbox_status"}
        assert "sandbox_stop" not in names

    def test_runtime_tools_appear_after_start(self, driver: SandboxToolDriver):
        driver.execute_tool("sandbox_start", {})
        tools = driver.list_tools()
        names = {t.name for t in tools}
        assert "shell_exec" in names
        assert "file_put" in names
        assert "file_get" in names
        assert "sandbox_stop" in names
        assert "sandbox_start" not in names

    def test_runtime_tools_disappear_after_stop(self, driver: SandboxToolDriver):
        driver.execute_tool("sandbox_start", {})
        driver.execute_tool("sandbox_stop", {})
        tools = driver.list_tools()
        names = {t.name for t in tools}
        assert "shell_exec" not in names
        assert "sandbox_start" in names
        assert "sandbox_stop" not in names

    def test_detects_already_running_backend(self):
        """When the backend is already running at construction time,
        the driver should expose runtime tools immediately."""
        adapter = FakeSandboxAdapter()
        adapter._running = True  # simulate pre-running backend
        td = SandboxToolDriver(_adapter=adapter)
        names = {t.name for t in td.list_tools()}
        assert "shell_exec" in names
        assert "sandbox_stop" in names
        assert "sandbox_start" not in names


# ---------------------------------------------------------------------------
# Lifecycle tools
# ---------------------------------------------------------------------------


class TestLifecycleTools:
    def test_start_returns_running(self, driver: SandboxToolDriver):
        result = json.loads(driver.execute_tool("sandbox_start", {}))
        assert result["running"] is True

    def test_stop_returns_stopped(self, driver: SandboxToolDriver):
        driver.execute_tool("sandbox_start", {})
        result = json.loads(driver.execute_tool("sandbox_stop", {}))
        assert result["status"] == "stopped"

    def test_status_reflects_state(self, driver: SandboxToolDriver):
        result = json.loads(driver.execute_tool("sandbox_status", {}))
        assert result["running"] is False

        driver.execute_tool("sandbox_start", {})
        result = json.loads(driver.execute_tool("sandbox_status", {}))
        assert result["running"] is True


# ---------------------------------------------------------------------------
# Runtime tools require running sandbox
# ---------------------------------------------------------------------------


class TestRuntimeGuard:
    def test_shell_exec_blocked_when_stopped(self, driver: SandboxToolDriver):
        result = json.loads(
            driver.execute_tool("shell_exec", {"command": "echo hi"})
        )
        assert "error" in result
        assert "not running" in result["error"].lower()

    def test_file_put_blocked_when_stopped(self, driver: SandboxToolDriver):
        result = json.loads(
            driver.execute_tool("file_put", {"path": "/workspace/x", "content": "y"})
        )
        assert "error" in result

    def test_file_get_blocked_when_stopped(self, driver: SandboxToolDriver):
        result = json.loads(
            driver.execute_tool("file_get", {"path": "/workspace/x"})
        )
        assert "error" in result


# ---------------------------------------------------------------------------
# shell_exec
# ---------------------------------------------------------------------------


class TestShellExec:
    def test_success(self, driver: SandboxToolDriver, adapter: FakeSandboxAdapter):
        driver.execute_tool("sandbox_start", {})
        result = json.loads(
            driver.execute_tool("shell_exec", {"command": "echo hello"})
        )
        assert result["exit_code"] == 0
        assert "echo hello" in result["stdout"]
        assert "echo hello" in adapter._exec_log

    def test_failure(self, driver: SandboxToolDriver):
        driver.execute_tool("sandbox_start", {})
        result = json.loads(
            driver.execute_tool("shell_exec", {"command": "fail now"})
        )
        assert result["exit_code"] == 1

    def test_custom_timeout(self, driver: SandboxToolDriver):
        driver.execute_tool("sandbox_start", {})
        result = json.loads(
            driver.execute_tool("shell_exec", {"command": "slow", "timeout": 60})
        )
        assert result["exit_code"] == 0


# ---------------------------------------------------------------------------
# file_put / file_get
# ---------------------------------------------------------------------------


class TestFileTransfer:
    def test_put_and_get_text(self, driver: SandboxToolDriver):
        driver.execute_tool("sandbox_start", {})
        driver.execute_tool(
            "file_put",
            {"path": "/workspace/hello.txt", "content": "Hello World"},
        )
        result = json.loads(
            driver.execute_tool("file_get", {"path": "/workspace/hello.txt"})
        )
        assert result["content"] == "Hello World"
        assert result["encoding"] == "utf-8"

    def test_put_base64_and_get(self, driver: SandboxToolDriver):
        driver.execute_tool("sandbox_start", {})
        binary = bytes([0x00, 0xFF, 0x80, 0x7F])
        b64 = base64.b64encode(binary).decode("ascii")
        driver.execute_tool(
            "file_put",
            {"path": "/workspace/data.bin", "content": b64, "encoding": "base64"},
        )
        result = json.loads(
            driver.execute_tool("file_get", {"path": "/workspace/data.bin"})
        )
        assert result["encoding"] == "base64"
        assert base64.b64decode(result["content"]) == binary

    def test_get_nonexistent_raises(self, driver: SandboxToolDriver):
        driver.execute_tool("sandbox_start", {})
        with pytest.raises(FileNotFoundError):
            driver.execute_tool("file_get", {"path": "/workspace/nope.txt"})


# ---------------------------------------------------------------------------
# Unknown tool
# ---------------------------------------------------------------------------


class TestUnknownTool:
    def test_raises_value_error(self, driver: SandboxToolDriver):
        driver.execute_tool("sandbox_start", {})
        with pytest.raises(ValueError, match="Unknown tool"):
            driver.execute_tool("totally_fake_tool", {})


# ---------------------------------------------------------------------------
# Meta
# ---------------------------------------------------------------------------


class TestMeta:
    def test_meta_fields(self):
        td = SandboxToolDriver(_adapter=FakeSandboxAdapter())
        assert td.meta.name == "Sandbox MCS ToolDriver"
        assert "orchestratable" in td.meta.capabilities
        assert td.meta.supported_llms is None
