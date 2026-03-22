"""Integration tests that start a Docker container with an SSH server.

Tests the full SSH adapter against a real sshd, verifying exec, file
upload/download, and working directory behavior.

Skipped automatically when Docker is not available.

Run explicitly:  uv run python -m pytest tests/test_ssh_integration.py -v
"""

from __future__ import annotations

import time
import uuid

import pytest

# -- Skip if Docker is not reachable --------------------------------------

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

from mcs.adapter.ssh.ssh_adapter import SSHAdapter


# ---------------------------------------------------------------------------
# Fixtures — spin up an Alpine container with OpenSSH
# ---------------------------------------------------------------------------

_RUN_ID = uuid.uuid4().hex[:8]
CONTAINER_NAME = f"mcs-ssh-test-{_RUN_ID}"
SSH_PORT = 2222  # Host port — avoids clashing with a real sshd
ROOT_PASSWORD = "testpass123"


@pytest.fixture(scope="module")
def ssh_container():
    """Start an Alpine container with sshd and return connection details."""
    client = docker.from_env()

    # Use Alpine with openssh installed inline — tiny and fast.
    # Pass entrypoint + command as lists to avoid shell quoting issues
    # across platforms (Windows Git Bash rewrites /bin/sh paths).
    setup_script = (
        "apk add --no-cache openssh && "
        "ssh-keygen -A && "
        f"echo 'root:{ROOT_PASSWORD}' | chpasswd && "
        "sed -i 's/^#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && "
        "echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config && "
        "mkdir -p /workspace && "
        "exec /usr/sbin/sshd -D -e"
    )
    container = client.containers.run(
        "alpine:latest",
        name=CONTAINER_NAME,
        entrypoint=["/bin/sh", "-c"],
        command=[setup_script],
        detach=True,
        ports={"22/tcp": SSH_PORT},
    )

    # Wait for sshd to be ready
    for _ in range(30):
        time.sleep(1)
        container.reload()
        if container.status == "running":
            # Try to check if sshd is listening
            exit_code, _ = container.exec_run("pgrep sshd")
            if exit_code == 0:
                break
    else:
        container.stop()
        container.remove(force=True)
        pytest.fail("SSH container did not start in time")

    yield {
        "host": "127.0.0.1",
        "port": SSH_PORT,
        "user": "root",
        "password": ROOT_PASSWORD,
    }

    # Cleanup
    try:
        container.stop(timeout=5)
        container.remove(force=True)
    except Exception:
        pass


@pytest.fixture(scope="module")
def adapter(ssh_container) -> SSHAdapter:
    """Create and start an SSHAdapter connected to the test container."""
    a = SSHAdapter(
        host=ssh_container["host"],
        user=ssh_container["user"],
        password=ssh_container["password"],
        port=ssh_container["port"],
        working_dir="/workspace",
        known_hosts_policy="auto_add",
    )
    a.start()
    yield a
    a.stop()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestSSHLifecycle:
    def test_start(self, adapter: SSHAdapter):
        result = adapter.status()
        assert result["running"] is True
        assert result["host"] == "127.0.0.1"

    def test_working_dir_created(self, adapter: SSHAdapter):
        result = adapter.exec("test -d /workspace && echo yes")
        assert result.exit_code == 0
        assert "yes" in result.stdout


class TestSSHExec:
    def test_echo(self, adapter: SSHAdapter):
        result = adapter.exec("echo hello from ssh")
        assert result.exit_code == 0
        assert "hello from ssh" in result.stdout

    def test_pwd_is_workspace(self, adapter: SSHAdapter):
        result = adapter.exec("pwd")
        assert result.exit_code == 0
        assert "/workspace" in result.stdout

    def test_nonzero_exit(self, adapter: SSHAdapter):
        result = adapter.exec("ls /nonexistent_dir_12345")
        assert result.exit_code != 0
        assert result.stderr != ""

    def test_multi_command(self, adapter: SSHAdapter):
        result = adapter.exec("echo first && echo second")
        assert result.exit_code == 0
        assert "first" in result.stdout
        assert "second" in result.stdout

    def test_env_variable(self, adapter: SSHAdapter):
        result = adapter.exec("export FOO=bar && echo $FOO")
        assert result.exit_code == 0
        assert "bar" in result.stdout


class TestSSHFileTransfer:
    def test_put_and_get_text(self, adapter: SSHAdapter):
        content = b"Hello from MCS SSH Adapter!"
        adapter.put_file("/workspace/hello.txt", content)

        retrieved = adapter.get_file("/workspace/hello.txt")
        assert retrieved == content

    def test_put_creates_nested_dirs(self, adapter: SSHAdapter):
        adapter.put_file(
            "/workspace/deep/nested/dir/file.txt",
            b"deep content",
        )
        result = adapter.exec("cat /workspace/deep/nested/dir/file.txt")
        assert "deep content" in result.stdout

    def test_roundtrip_script(self, adapter: SSHAdapter):
        """Upload a script, make it executable, run it."""
        script = b"#!/bin/sh\necho 'SSH sandbox works!'\nexit 0\n"
        adapter.put_file("/workspace/test.sh", script)
        adapter.exec("chmod +x /workspace/test.sh")

        result = adapter.exec("/workspace/test.sh")
        assert result.exit_code == 0
        assert "SSH sandbox works!" in result.stdout

    def test_binary_roundtrip(self, adapter: SSHAdapter):
        binary = bytes(range(256))
        adapter.put_file("/workspace/data.bin", binary)
        retrieved = adapter.get_file("/workspace/data.bin")
        assert retrieved == binary


class TestSSHStopResume:
    def test_stop_and_reconnect(self, ssh_container, adapter: SSHAdapter):
        """Verify we can disconnect and reconnect."""
        # Write a file
        adapter.put_file("/workspace/persist.txt", b"I survive disconnects")

        # Disconnect
        adapter.stop()
        assert adapter.status()["running"] is False

        # Reconnect
        adapter.start()
        assert adapter.status()["running"] is True

        # File should still be there
        result = adapter.exec("cat /workspace/persist.txt")
        assert "I survive disconnects" in result.stdout
