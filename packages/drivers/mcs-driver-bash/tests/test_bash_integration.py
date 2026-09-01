"""Integration: the bash tool over a real Docker container.

Skipped automatically when Docker is not reachable. What changed against the
old sandbox suite is the LINE, not the coverage: lifecycle and file transfer
are exercised as *client/adapter* operations (the fixture starts the container,
provisioning uses the adapter's API), while the model-facing surface is the one
`bash` tool -- exactly the split the harness survey measured.

Run explicitly with:  uv run python -m pytest tests/test_bash_integration.py -v
"""

from __future__ import annotations

import uuid

import pytest

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

from mcs.driver.bash import BashToolDriver
from mcs.adapter.docker.docker_adapter import DockerAdapter

_RUN_ID = uuid.uuid4().hex[:8]
CONTAINER_NAME = f"mcs-bash-test-{_RUN_ID}"
VOLUME_NAME = f"mcs-bash-test-vol-{_RUN_ID}"


@pytest.fixture(scope="module")
def adapter():
    """The modality, operated by the CLIENT: started here, cleaned up here."""
    a = DockerAdapter(
        image="alpine:latest",
        container_name=CONTAINER_NAME,
        volume=VOLUME_NAME,
        working_dir="/workspace",
    )
    a.start()
    yield a
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


@pytest.fixture(scope="module")
def bash(adapter):
    return BashToolDriver(adapter)


class TestBashOverDocker:

    def test_echo(self, bash):
        result = bash.execute_tool("bash", {"command": "echo hello"})
        assert result["exit_code"] == 0
        assert "hello" in result["stdout"]

    def test_the_workdir_is_the_adapters_choice(self, bash):
        result = bash.execute_tool("bash", {"command": "pwd"})
        assert "/workspace" in result["stdout"]

    def test_nonzero_exit_code(self, bash):
        assert bash.execute_tool(
            "bash", {"command": "ls /nonexistent_dir"})["exit_code"] != 0

    def test_install_and_use_a_tool(self, bash):
        """The workstation pattern: the model may shape its own environment."""
        install = bash.execute_tool(
            "bash", {"command": "apk add --no-cache curl 2>&1", "timeout": 60})
        assert install["exit_code"] == 0
        use = bash.execute_tool("bash", {"command": "curl --version"})
        assert use["exit_code"] == 0
        assert "curl" in use["stdout"].lower()


class TestProvisioningIsClientBusiness:
    """put_file/get_file live on the ADAPTER as client API -- the model gets no
    file tools here; inside its environment, bash touches files itself."""

    def test_client_provisions_model_consumes(self, adapter, bash):
        adapter.put_file("/workspace/task.txt", b"Hello from the client!")
        result = bash.execute_tool("bash", {"command": "cat /workspace/task.txt"})
        assert "Hello from the client!" in result["stdout"]

    def test_model_produces_client_collects(self, adapter, bash):
        bash.execute_tool(
            "bash", {"command": "echo result > /workspace/out.txt"})
        assert b"result" in adapter.get_file("/workspace/out.txt")


class TestLifecycleIsClientBusiness:

    def test_state_survives_a_client_side_stop_start(self, adapter, bash):
        bash.execute_tool(
            "bash", {"command": "echo persistent > /workspace/keep.txt"})
        adapter.stop()
        adapter.start()
        result = bash.execute_tool("bash", {"command": "cat /workspace/keep.txt"})
        assert "persistent" in result["stdout"]
