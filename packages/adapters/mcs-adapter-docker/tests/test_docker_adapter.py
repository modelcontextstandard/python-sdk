"""Unit tests for the DockerAdapter.

These tests mock the docker-py client so they run without a Docker daemon.
Integration tests that actually start containers should be in a separate
test suite marked with ``@pytest.mark.integration``.
"""

from __future__ import annotations

import io
import json
import tarfile
from typing import Any, Dict
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from docker.errors import NotFound as ContainerNotFound

from mcs.adapter.docker.docker_adapter import DockerAdapter, ExecResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_tar(filename: str, content: bytes) -> bytes:
    """Create a tar archive in memory containing a single file."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo(name=filename)
        info.size = len(content)
        tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_docker_client():
    """Return a fully mocked docker.DockerClient."""
    with patch("mcs.adapter.docker.docker_adapter.docker") as mock_docker:
        client = MagicMock()
        mock_docker.from_env.return_value = client
        mock_docker.DockerClient.return_value = client
        mock_docker.errors.NotFound = Exception
        yield client


@pytest.fixture
def adapter(mock_docker_client) -> DockerAdapter:
    """Create an adapter with a mocked Docker client."""
    return DockerAdapter(
        image="ubuntu:24.04",
        container_name="test-sandbox",
        volume="test-volume",
    )


# ---------------------------------------------------------------------------
# Constructor
# ---------------------------------------------------------------------------


class TestConstructor:
    def test_default_values(self, mock_docker_client):
        a = DockerAdapter()
        assert a._image == "ubuntu:24.04"
        assert a._container_name == "mcs-sandbox"
        assert a._working_dir == "/workspace"

    def test_custom_values(self, mock_docker_client):
        a = DockerAdapter(
            image="python:3.12",
            container_name="my-ws",
            volume="my-vol",
            working_dir="/home/agent",
        )
        assert a._image == "python:3.12"
        assert a._container_name == "my-ws"
        assert a._volume == "my-vol"
        assert a._working_dir == "/home/agent"

    def test_custom_docker_url(self):
        with patch("mcs.adapter.docker.docker_adapter.docker") as mock_docker:
            client = MagicMock()
            mock_docker.DockerClient.return_value = client
            a = DockerAdapter(docker_base_url="tcp://remote:2375")
            mock_docker.DockerClient.assert_called_once_with(
                base_url="tcp://remote:2375"
            )


# ---------------------------------------------------------------------------
# Lifecycle: start
# ---------------------------------------------------------------------------


class TestStart:
    def test_creates_new_container(self, adapter, mock_docker_client):
        mock_docker_client.containers.get.side_effect = ContainerNotFound("not found")
        container = MagicMock()
        container.status = "running"
        container.id = "abc123"
        mock_docker_client.containers.run.return_value = container

        result = adapter.start()
        assert result["running"] is True
        mock_docker_client.containers.run.assert_called_once()

    def test_resumes_stopped_container(self, adapter, mock_docker_client):
        container = MagicMock()
        container.status = "exited"
        mock_docker_client.containers.get.return_value = container

        # After start + reload the container is running
        def reload():
            container.status = "running"

        container.reload = reload

        result = adapter.start()
        container.start.assert_called_once()
        assert result["running"] is True

    def test_reuses_running_container(self, adapter, mock_docker_client):
        container = MagicMock()
        container.status = "running"
        mock_docker_client.containers.get.return_value = container

        result = adapter.start()
        container.start.assert_not_called()
        assert result["running"] is True


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------


class TestStatus:
    def test_status_when_no_container(self, adapter, mock_docker_client):
        mock_docker_client.containers.get.side_effect = ContainerNotFound("not found")
        result = adapter.status()
        assert result["running"] is False
        assert result["exists"] is False

    def test_status_when_running(self, adapter, mock_docker_client):
        container = MagicMock()
        container.status = "running"
        mock_docker_client.containers.get.return_value = container

        # First start to set self._container
        adapter.start()
        result = adapter.status()
        assert result["running"] is True
        assert result["exists"] is True
