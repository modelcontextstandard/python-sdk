"""MCPLocalAdapter — runs local MCP servers via subprocess or Docker.

Implements the MCPPort protocol for MCP servers that communicate over
stdio (stdin/stdout JSON-RPC).  This is the standard transport for local
MCP servers like ``npx @modelcontextprotocol/server-filesystem``.

Resolution strategy (automatic):
1. **Docker available** → run the MCP server command inside an isolated
   container, mapping required volumes.  Best for untrusted servers or
   environments where the host shouldn't be polluted with dependencies.
2. **No Docker** (e.g. inside an existing container) → spawn the MCP
   server as a local subprocess.  Necessary evil, but it's exactly what
   MCP itself does.

The adapter auto-detects Docker availability at ``connect()`` time unless
explicitly overridden via the ``transport`` parameter.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import threading
from typing import Any, Dict, List, Optional, Sequence

from .ports import MCPToolDef, MCPToolResult

logger = logging.getLogger(__name__)

_JSONRPC_VERSION = "2.0"


class MCPLocalAdapter:
    """Adapter that spawns a local MCP server and speaks JSON-RPC over stdio.

    Parameters
    ----------
    command : str
        The executable to run (e.g. ``"npx"``, ``"uvx"``, ``"node"``).
    args : list[str]
        Arguments passed to the command.
    env : dict | None
        Extra environment variables for the subprocess.
    transport : str
        Transport mode: ``"auto"`` (detect Docker, fall back to process),
        ``"docker"``, or ``"process"``.
    docker_image : str | None
        Docker image to use when running in Docker mode.  When *None*,
        auto-selects based on the command (``node:22-slim`` for npx,
        ``python:3.12-slim`` for uvx/python).
    docker_volumes : dict | None
        Volume mappings for Docker mode, e.g.
        ``{"/host/path": {"bind": "/container/path", "mode": "ro"}}``.
    docker_network : str | None
        Docker network to attach the container to (for servers that need
        network access, e.g. database MCP servers).
    working_dir : str | None
        Working directory for the subprocess / container.
    startup_timeout : int
        Seconds to wait for the MCP server to respond to ``initialize``.
    """

    def __init__(
        self,
        *,
        command: str,
        args: Optional[Sequence[str]] = None,
        env: Optional[Dict[str, str]] = None,
        transport: str = "auto",
        docker_image: Optional[str] = None,
        docker_volumes: Optional[Dict[str, Any]] = None,
        docker_network: Optional[str] = None,
        working_dir: Optional[str] = None,
        startup_timeout: int = 30,
    ) -> None:
        self._command = command
        self._args = list(args or [])
        self._env = env or {}
        self._transport = transport
        self._docker_image = docker_image
        self._docker_volumes = docker_volumes or {}
        self._docker_network = docker_network
        self._working_dir = working_dir
        self._startup_timeout = startup_timeout

        self._process: Optional[subprocess.Popen] = None
        self._docker_container: Any = None  # docker.models.containers.Container
        self._request_id = 0
        self._connected = False
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # MCPPort interface
    # ------------------------------------------------------------------

    def connect(self) -> None:
        """Spawn the MCP server and perform the initialize handshake."""
        resolved = self._resolve_transport()
        logger.info("MCP local transport resolved to: %s", resolved)

        if resolved == "docker":
            self._start_docker()
        else:
            self._start_process()

        # MCP initialize handshake over stdio.
        resp = self._rpc("initialize", {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {
                "name": "mcs-adapter-mcp-local",
                "version": "0.1.0",
            },
        })
        logger.info(
            "MCP local server initialised: server=%s, protocol=%s",
            resp.get("serverInfo", {}).get("name", "unknown"),
            resp.get("protocolVersion", "unknown"),
        )
        self._notify("notifications/initialized", {})
        self._connected = True

    def disconnect(self) -> None:
        """Shut down the MCP server process or container."""
        self._connected = False
        if self._process is not None:
            try:
                self._process.stdin.close()  # type: ignore[union-attr]
                self._process.terminate()
                self._process.wait(timeout=5)
            except Exception:
                self._process.kill()
            finally:
                self._process = None
            logger.info("MCP local subprocess terminated")

        if self._docker_container is not None:
            try:
                self._docker_container.stop(timeout=5)
                self._docker_container.remove(force=True)
            except Exception:
                pass
            finally:
                self._docker_container = None
            logger.info("MCP Docker container removed")

    def list_tools(self) -> List[MCPToolDef]:
        """Retrieve tools from the local MCP server."""
        self._ensure_connected()
        resp = self._rpc("tools/list", {})
        tools: List[MCPToolDef] = []
        for t in resp.get("tools", []):
            tools.append(MCPToolDef(
                name=t["name"],
                description=t.get("description", ""),
                input_schema=t.get("inputSchema", {}),
            ))
        logger.info("MCP local server exposes %d tools", len(tools))
        return tools

    def call_tool(
        self, name: str, arguments: Dict[str, Any]
    ) -> MCPToolResult:
        """Invoke a tool on the local MCP server."""
        self._ensure_connected()
        resp = self._rpc("tools/call", {
            "name": name,
            "arguments": arguments,
        })
        is_error = resp.get("isError", False)
        content = resp.get("content", [])
        text_parts = []
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                text_parts.append(block.get("text", ""))
        result_text = "\n".join(text_parts) if text_parts else content
        return MCPToolResult(content=result_text, is_error=is_error)

    # ------------------------------------------------------------------
    # Transport resolution
    # ------------------------------------------------------------------

    def _resolve_transport(self) -> str:
        """Determine whether to use Docker or a plain subprocess."""
        if self._transport == "docker":
            return "docker"
        if self._transport == "process":
            return "process"

        # Auto-detect: try Docker first.
        if self._is_docker_available():
            logger.info("Docker detected — running MCP server in container")
            return "docker"

        logger.info("Docker not available — falling back to subprocess")
        return "process"

    @staticmethod
    def _is_docker_available() -> bool:
        """Check whether Docker is reachable."""
        try:
            import docker as docker_lib
            client = docker_lib.from_env()
            client.ping()
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Subprocess transport
    # ------------------------------------------------------------------

    def _start_process(self) -> None:
        """Spawn the MCP server as a local subprocess."""
        cmd = [self._command] + self._args
        env = {**os.environ, **self._env}

        logger.info("Spawning MCP subprocess: %s", " ".join(cmd))
        self._process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            cwd=self._working_dir,
        )

    # ------------------------------------------------------------------
    # Docker transport
    # ------------------------------------------------------------------

    def _start_docker(self) -> None:
        """Run the MCP server inside a Docker container with stdio."""
        import docker as docker_lib

        client = docker_lib.from_env()
        image = self._docker_image or self._guess_image()

        cmd_parts = [self._command] + self._args
        container_cmd = " ".join(cmd_parts)

        run_kwargs: Dict[str, Any] = {
            "image": image,
            "command": f"/bin/sh -c '{container_cmd}'",
            "detach": True,
            "stdin_open": True,
            "environment": self._env,
        }
        if self._docker_volumes:
            run_kwargs["volumes"] = self._docker_volumes
        if self._docker_network:
            run_kwargs["network"] = self._docker_network
        if self._working_dir:
            run_kwargs["working_dir"] = self._working_dir

        logger.info(
            "Starting MCP Docker container: image=%s, cmd=%s",
            image, container_cmd,
        )
        self._docker_container = client.containers.run(**run_kwargs)

        # Attach to container's stdin/stdout for stdio transport.
        self._process = self._docker_container.attach(
            stdin=True, stdout=True, stderr=True, stream=True,
        )
        # Re-wrap as a subprocess-like object for unified _rpc().
        self._process = _DockerStdioWrapper(self._docker_container)

    def _guess_image(self) -> str:
        """Pick a Docker image based on the command."""
        cmd = self._command.lower()
        if cmd in ("npx", "node", "npm"):
            return "node:22-slim"
        if cmd in ("uvx", "uv", "python", "python3", "pip"):
            return "python:3.12-slim"
        return "ubuntu:24.04"

    # ------------------------------------------------------------------
    # JSON-RPC over stdio
    # ------------------------------------------------------------------

    def _next_id(self) -> int:
        self._request_id += 1
        return self._request_id

    def _rpc(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Send a JSON-RPC request via stdin and read the result from stdout."""
        if self._process is None:
            raise RuntimeError("MCP server process not running")

        payload = {
            "jsonrpc": _JSONRPC_VERSION,
            "id": self._next_id(),
            "method": method,
            "params": params,
        }
        request_id = payload["id"]
        msg = json.dumps(payload) + "\n"

        with self._lock:
            self._process.stdin.write(msg.encode("utf-8"))  # type: ignore[union-attr]
            self._process.stdin.flush()  # type: ignore[union-attr]

            # Read lines until we get a JSON-RPC response matching our id.
            while True:
                line = self._process.stdout.readline()  # type: ignore[union-attr]
                if not line:
                    raise RuntimeError(
                        "MCP server closed stdout unexpectedly"
                    )
                line_str = line.decode("utf-8").strip()
                if not line_str:
                    continue
                try:
                    data = json.loads(line_str)
                except json.JSONDecodeError:
                    # Skip non-JSON lines (server logs, etc.).
                    logger.debug("Skipping non-JSON line: %s", line_str[:120])
                    continue

                # Skip notifications (no "id" field).
                if "id" not in data:
                    continue

                if data["id"] != request_id:
                    logger.debug(
                        "Ignoring response with mismatched id: %s", data["id"]
                    )
                    continue

                if "error" in data:
                    err = data["error"]
                    raise RuntimeError(
                        f"MCP JSON-RPC error {err.get('code')}: "
                        f"{err.get('message')}"
                    )
                return data.get("result", {})

    def _notify(self, method: str, params: Dict[str, Any]) -> None:
        """Send a JSON-RPC notification (no response expected)."""
        if self._process is None:
            return
        payload = {
            "jsonrpc": _JSONRPC_VERSION,
            "method": method,
            "params": params,
        }
        msg = json.dumps(payload) + "\n"
        with self._lock:
            self._process.stdin.write(msg.encode("utf-8"))  # type: ignore[union-attr]
            self._process.stdin.flush()  # type: ignore[union-attr]

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _ensure_connected(self) -> None:
        if not self._connected:
            raise RuntimeError(
                "Not connected to MCP server. Call connect() first."
            )


class _DockerStdioWrapper:
    """Wraps a Docker container's attach socket to look like a subprocess.

    Provides ``.stdin`` and ``.stdout`` attributes with ``write()``,
    ``flush()``, and ``readline()`` methods so the JSON-RPC transport
    can use it identically to a ``subprocess.Popen`` object.
    """

    def __init__(self, container: Any) -> None:
        self._container = container
        self._socket = container.attach_socket(
            params={"stdin": 1, "stdout": 1, "stderr": 0, "stream": 1}
        )
        self.stdin = self
        self.stdout = self
        self._read_buffer = b""

    def write(self, data: bytes) -> None:
        self._socket._sock.sendall(data)

    def flush(self) -> None:
        pass  # Socket sends immediately.

    def readline(self) -> bytes:
        while b"\n" not in self._read_buffer:
            chunk = self._socket._sock.recv(4096)
            if not chunk:
                # Return what we have, or empty if truly closed.
                remaining = self._read_buffer
                self._read_buffer = b""
                return remaining
            self._read_buffer += chunk
        idx = self._read_buffer.index(b"\n")
        line = self._read_buffer[: idx + 1]
        self._read_buffer = self._read_buffer[idx + 1 :]
        return line

    def close(self) -> None:
        try:
            self._socket.close()
        except Exception:
            pass
