"""Docker adapter implementing the SandboxPort protocol.

Manages a persistent Docker container backed by a named volume.
The container is created on first ``start()`` and reused on subsequent calls.
Stopping the container preserves the volume so all installed tools,
written files and configuration survive across sessions.
"""

from __future__ import annotations

import base64
import io
import json
import logging
import tarfile
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

import docker
from docker.errors import NotFound as ContainerNotFound
from docker.models.containers import Container

logger = logging.getLogger(__name__)


@dataclass
class ExecResult:
    """Result of a command execution inside the sandbox."""

    exit_code: int
    stdout: str
    stderr: str


class DockerAdapter:
    """Adapter that runs sandbox operations inside a Docker container.

    Parameters
    ----------
    image : str
        Docker image to use (e.g. ``"ubuntu:24.04"``).
    container_name : str
        Name for the Docker container. Must be unique per sandbox.
    volume : str | None
        Named Docker volume mounted at ``/workspace``.  When *None* an
        anonymous volume is used (state is lost when the container is
        removed).
    home_volume : str | bool | None
        Named Docker volume mounted at ``/root`` to persist the home
        directory (nvm, dotfiles, shell history, etc.).
        - ``True`` (default when *volume* is set): auto-generates a name
          from *volume* + ``"-home"`` (e.g. ``"my-vol"`` → ``"my-vol-home"``).
        - A string: use that exact volume name.
        - ``None`` / ``False``: no home volume.
    ports : dict | None
        Port mappings from host to container, e.g.
        ``{"4321/tcp": 4321}`` or ``{"8080/tcp": 8080, "3000/tcp": 3000}``.
        Ports are set at container creation time.  Changing ports requires
        recreating the container (the volume preserves state).
    resources : dict | None
        Optional resource constraints forwarded to the Docker engine
        (e.g. ``{"mem_limit": "2g", "nano_cpus": 2_000_000_000}``).
    working_dir : str
        Default working directory inside the container.
    environment : dict | None
        Environment variables passed into the container.
    docker_base_url : str | None
        Custom Docker daemon URL.  Defaults to the local socket.
    """

    def __init__(
        self,
        *,
        image: str = "ubuntu:24.04",
        container_name: str = "mcs-sandbox",
        volume: Optional[str] = None,
        home_volume: Optional[Any] = True,
        ports: Optional[Dict[str, int]] = None,
        resources: Optional[Dict[str, Any]] = None,
        working_dir: str = "/workspace",
        environment: Optional[Dict[str, str]] = None,
        docker_base_url: Optional[str] = None,
    ) -> None:
        self._image = image
        self._container_name = container_name
        self._volume = volume
        # Resolve home_volume: True → auto-name, str → use as-is, falsy → None
        if home_volume is True and volume:
            self._home_volume: Optional[str] = f"{volume}-home"
        elif isinstance(home_volume, str):
            self._home_volume = home_volume
        else:
            self._home_volume = None
        self._ports = ports or {}
        self._resources = resources or {}
        self._working_dir = working_dir
        self._environment = environment or {}
        self._container: Optional[Container] = None

        if docker_base_url:
            self._client = docker.DockerClient(base_url=docker_base_url)
        else:
            self._client = docker.from_env()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> Dict[str, Any]:
        """Start or resume the sandbox container.

        Returns a status dict with container metadata.
        """
        try:
            self._container = self._client.containers.get(self._container_name)
            if self._container.status != "running":
                logger.info(
                    "Resuming stopped container %s", self._container_name
                )
                self._container.start()
                self._container.reload()
            else:
                logger.info(
                    "Container %s already running", self._container_name
                )
        except ContainerNotFound:
            logger.info(
                "Creating new container %s from image %s",
                self._container_name,
                self._image,
            )
            volumes: Dict[str, Any] = {}
            if self._volume:
                volumes[self._volume] = {
                    "bind": self._working_dir,
                    "mode": "rw",
                }
            if self._home_volume:
                volumes[self._home_volume] = {
                    "bind": "/root",
                    "mode": "rw",
                }

            run_kwargs: Dict[str, Any] = {
                "image": self._image,
                "name": self._container_name,
                "detach": True,
                "tty": True,
                "stdin_open": True,
                "working_dir": self._working_dir,
                "volumes": volumes,
                "environment": self._environment,
            }
            if self._ports:
                run_kwargs["ports"] = self._ports
            run_kwargs.update(self._resources)

            self._container = self._client.containers.run(**run_kwargs)

        return self.status()

    def stop(self) -> Dict[str, Any]:
        """Stop the sandbox container (preserving the volume)."""
        if self._container is None:
            return {"status": "not_running"}
        try:
            self._container.reload()
            if self._container.status == "running":
                self._container.stop(timeout=10)
                logger.info("Container %s stopped", self._container_name)
        except ContainerNotFound:
            pass
        return {"status": "stopped", "container": self._container_name}

    def status(self) -> Dict[str, Any]:
        """Return current sandbox status."""
        if self._container is None:
            try:
                self._container = self._client.containers.get(
                    self._container_name
                )
            except ContainerNotFound:
                return {
                    "running": False,
                    "container": self._container_name,
                    "exists": False,
                }
        self._container.reload()
        return {
            "running": self._container.status == "running",
            "container": self._container_name,
            "image": self._image,
            "exists": True,
            "working_dir": self._working_dir,
        }

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def exec(self, command: str, *, timeout: int = 30) -> ExecResult:
        """Execute a shell command inside the running container.

        Parameters
        ----------
        command : str
            Shell command (passed to ``/bin/sh -c``).
        timeout : int
            Maximum execution time in seconds.

        Returns
        -------
        ExecResult
            Dataclass with ``exit_code``, ``stdout``, ``stderr``.
        """
        self._ensure_running()
        assert self._container is not None

        exec_id = self._container.client.api.exec_create(
            self._container.id,
            ["/bin/sh", "-c", command],
            workdir=self._working_dir,
            stdout=True,
            stderr=True,
        )
        output = self._container.client.api.exec_start(exec_id["Id"])
        inspect = self._container.client.api.exec_inspect(exec_id["Id"])

        stdout_str = output.decode("utf-8", errors="replace") if output else ""

        return ExecResult(
            exit_code=inspect.get("ExitCode", -1),
            stdout=stdout_str,
            stderr="",
        )

    # ------------------------------------------------------------------
    # File transfer
    # ------------------------------------------------------------------

    def put_file(self, path: str, content: bytes) -> None:
        """Write *content* to *path* inside the container.

        Parent directories are created automatically via a tar archive
        upload (Docker ``put_archive`` API).
        """
        self._ensure_running()
        assert self._container is not None

        # Docker put_archive expects a tar stream.
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            info = tarfile.TarInfo(name=path.split("/")[-1])
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
        buf.seek(0)

        # Ensure parent directory exists.
        parent = "/".join(path.split("/")[:-1]) or "/"
        self._container.client.api.exec_create(
            self._container.id, ["mkdir", "-p", parent]
        )
        self._container.client.api.exec_start(
            self._container.client.api.exec_create(
                self._container.id, ["mkdir", "-p", parent]
            )["Id"]
        )

        self._container.put_archive(parent, buf)
        logger.info("Uploaded %d bytes to %s", len(content), path)

    def get_file(self, path: str) -> bytes:
        """Read a file from *path* inside the container.

        Returns the raw bytes of the file content.
        """
        self._ensure_running()
        assert self._container is not None

        stream, _stat = self._container.get_archive(path)
        buf = io.BytesIO()
        for chunk in stream:
            buf.write(chunk)
        buf.seek(0)

        with tarfile.open(fileobj=buf, mode="r") as tar:
            member = tar.getmembers()[0]
            f = tar.extractfile(member)
            if f is None:
                raise FileNotFoundError(f"Cannot read {path} from container")
            return f.read()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _ensure_running(self) -> None:
        """Raise if the container is not running."""
        if self._container is None:
            raise RuntimeError(
                "Sandbox not started. Call start() first."
            )
        self._container.reload()
        if self._container.status != "running":
            raise RuntimeError(
                f"Container {self._container_name} is {self._container.status}, "
                "not running. Call start() to resume."
            )
