"""Integration tests that start a real Docker container.

These tests are skipped automatically when Docker is not available
(e.g. Docker Desktop not running on Windows/macOS, or docker not
installed on Linux).

Run explicitly with:  uv run python -m pytest tests/test_sandbox_integration.py -v
"""

from __future__ import annotations

import json
import uuid

import pytest

# -- Skip the entire module if docker-py can't connect ---------------------

try:
    import docker

    _client = docker.from_env()
    _client.ping()
    DOCKER_AVAILABLE = True
except Exception:
    DOCKER_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not DOCKER_AVAILABLE,
    reason="Docker daemon not reachable — is Docker Desktop running?",
)

from mcs.driver.sandbox.tooldriver import SandboxToolDriver
from mcs.adapter.docker.docker_adapter import DockerAdapter


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

# Use a unique container name per test run so parallel CI doesn't collide.
_RUN_ID = uuid.uuid4().hex[:8]
CONTAINER_NAME = f"mcs-sandbox-test-{_RUN_ID}"
VOLUME_NAME = f"mcs-sandbox-test-vol-{_RUN_ID}"


@pytest.fixture(scope="module")
def sandbox_driver():
    """Create a SandboxToolDriver backed by a real Docker container."""
    adapter = DockerAdapter(
        image="alpine:latest",  # Small, fast to pull
        container_name=CONTAINER_NAME,
        volume=VOLUME_NAME,
        working_dir="/workspace",
    )
    driver = SandboxToolDriver(_adapter=adapter)
    yield driver

    # Cleanup: stop and remove the container + volume
    try:
        client = docker.from_env()
        try:
            container = client.containers.get(CONTAINER_NAME)
            container.stop(timeout=5)
            container.remove(force=True)
        except docker.errors.NotFound:
            pass
        try:
            client.volumes.get(VOLUME_NAME).remove(force=True)
        except docker.errors.NotFound:
            pass
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestDockerLifecycle:
    def test_start(self, sandbox_driver: SandboxToolDriver):
        result = json.loads(sandbox_driver.execute_tool("sandbox_start", {}))
        assert result["running"] is True
        assert result["exists"] is True

    def test_status_after_start(self, sandbox_driver: SandboxToolDriver):
        result = json.loads(sandbox_driver.execute_tool("sandbox_status", {}))
        assert result["running"] is True


class TestDockerShellExec:
    def test_echo(self, sandbox_driver: SandboxToolDriver):
        # Ensure started (idempotent)
        sandbox_driver.execute_tool("sandbox_start", {})

        result = json.loads(
            sandbox_driver.execute_tool("shell_exec", {"command": "echo hello"})
        )
        assert result["exit_code"] == 0
        assert "hello" in result["stdout"]

    def test_pwd_is_workspace(self, sandbox_driver: SandboxToolDriver):
        result = json.loads(
            sandbox_driver.execute_tool("shell_exec", {"command": "pwd"})
        )
        assert result["exit_code"] == 0
        assert "/workspace" in result["stdout"]

    def test_install_and_use_tool(self, sandbox_driver: SandboxToolDriver):
        """Verify we can install a package and use it — the workstation pattern."""
        # Alpine uses apk
        install = json.loads(
            sandbox_driver.execute_tool(
                "shell_exec",
                {"command": "apk add --no-cache curl 2>&1", "timeout": 60},
            )
        )
        assert install["exit_code"] == 0

        use = json.loads(
            sandbox_driver.execute_tool(
                "shell_exec", {"command": "curl --version | head -1"}
            )
        )
        assert use["exit_code"] == 0
        assert "curl" in use["stdout"].lower()

    def test_nonzero_exit_code(self, sandbox_driver: SandboxToolDriver):
        result = json.loads(
            sandbox_driver.execute_tool(
                "shell_exec", {"command": "ls /nonexistent_dir"}
            )
        )
        assert result["exit_code"] != 0


class TestDockerFileTransfer:
    def test_put_and_get_text(self, sandbox_driver: SandboxToolDriver):
        sandbox_driver.execute_tool("sandbox_start", {})

        # Upload
        put_result = json.loads(
            sandbox_driver.execute_tool(
                "file_put",
                {
                    "path": "/workspace/test.txt",
                    "content": "Hello from MCS Sandbox!",
                },
            )
        )
        assert put_result["bytes_written"] == len("Hello from MCS Sandbox!")

        # Verify via shell
        cat_result = json.loads(
            sandbox_driver.execute_tool(
                "shell_exec", {"command": "cat /workspace/test.txt"}
            )
        )
        assert "Hello from MCS Sandbox!" in cat_result["stdout"]

        # Download
        get_result = json.loads(
            sandbox_driver.execute_tool(
                "file_get", {"path": "/workspace/test.txt"}
            )
        )
        assert get_result["content"] == "Hello from MCS Sandbox!"
        assert get_result["encoding"] == "utf-8"

    def test_put_creates_nested_dirs(self, sandbox_driver: SandboxToolDriver):
        sandbox_driver.execute_tool(
            "file_put",
            {
                "path": "/workspace/deep/nested/dir/file.txt",
                "content": "deep content",
            },
        )
        result = json.loads(
            sandbox_driver.execute_tool(
                "shell_exec",
                {"command": "cat /workspace/deep/nested/dir/file.txt"},
            )
        )
        assert "deep content" in result["stdout"]

    def test_roundtrip_script(self, sandbox_driver: SandboxToolDriver):
        """Upload a script, make it executable, run it, capture output."""
        script = "#!/bin/sh\necho 'MCS sandbox works!'\nexit 0\n"
        sandbox_driver.execute_tool(
            "file_put",
            {"path": "/workspace/test.sh", "content": script},
        )
        sandbox_driver.execute_tool(
            "shell_exec", {"command": "chmod +x /workspace/test.sh"}
        )
        result = json.loads(
            sandbox_driver.execute_tool(
                "shell_exec", {"command": "/workspace/test.sh"}
            )
        )
        assert result["exit_code"] == 0
        assert "MCS sandbox works!" in result["stdout"]


class TestDockerStop:
    def test_stop_and_resume(self, sandbox_driver: SandboxToolDriver):
        """Verify that state persists across stop/start cycles."""
        sandbox_driver.execute_tool("sandbox_start", {})

        # Write a file
        sandbox_driver.execute_tool(
            "file_put",
            {"path": "/workspace/persist.txt", "content": "I survive restarts"},
        )

        # Stop
        stop_result = json.loads(sandbox_driver.execute_tool("sandbox_stop", {}))
        assert stop_result["status"] == "stopped"

        # Resume
        start_result = json.loads(sandbox_driver.execute_tool("sandbox_start", {}))
        assert start_result["running"] is True

        # File should still be there
        cat = json.loads(
            sandbox_driver.execute_tool(
                "shell_exec", {"command": "cat /workspace/persist.txt"}
            )
        )
        assert "I survive restarts" in cat["stdout"]
