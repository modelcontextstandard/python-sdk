"""Sandbox ToolDriver — exposes an isolated compute environment as MCS tools.

Tools are surfaced **dynamically**: when the sandbox is stopped only lifecycle
tools are visible.  Once started, ``shell_exec``, ``file_put`` and
``file_get`` appear in the tool list so the LLM learns that it must start
the sandbox before executing commands.
"""

from __future__ import annotations

import base64
import json
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from mcs.driver.core.mcs_driver_interface import DriverBinding, DriverMeta
from mcs.driver.core.mcs_tool_driver_interface import (
    MCSToolDriver,
    Tool,
    ToolParameter,
)

from .ports import SandboxPort

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class _SandboxToolDriverMeta(DriverMeta):
    id: str = "b2c3d4e5-sb01-4000-9000-sandbox00000001"
    name: str = "Sandbox MCS ToolDriver"
    version: str = "0.1.0"
    bindings: tuple = (
        DriverBinding(
            capability="sandbox", adapter="*", spec_format="Custom"
        ),
    )
    supported_llms: None = None
    capabilities: tuple = ("orchestratable",)


# -- Static tool definitions ------------------------------------------------

_TOOL_START = Tool(
    name="sandbox_start",
    description=(
        "Start or resume the sandbox environment. "
        "Must be called before any other sandbox operations. "
        "Once started, additional tools become available: "
        "shell_exec, file_put and file_get. "
        "Returns status metadata including the working directory."
    ),
    parameters=[],
)

_TOOL_STOP = Tool(
    name="sandbox_stop",
    description=(
        "Stop the sandbox environment. State is preserved — "
        "a subsequent sandbox_start will resume where you left off."
    ),
    parameters=[],
)

_TOOL_STATUS = Tool(
    name="sandbox_status",
    description="Check whether the sandbox is currently running.",
    parameters=[],
)

_RUNTIME_TOOLS: List[Tool] = [
    Tool(
        name="shell_exec",
        description=(
            "Execute a shell command inside the sandbox and return "
            "stdout, stderr and the exit code. "
            "Commands run in the sandbox working directory."
        ),
        parameters=[
            ToolParameter(
                name="command",
                description="Shell command to execute (passed to /bin/sh -c).",
                required=True,
                schema={"type": "string"},
            ),
            ToolParameter(
                name="timeout",
                description="Maximum execution time in seconds (default 30).",
                required=False,
                schema={"type": "integer", "default": 30},
            ),
        ],
    ),
    Tool(
        name="file_put",
        description=(
            "Upload a file into the sandbox. Content is provided as a "
            "UTF-8 string (for text files) or as a base64-encoded string "
            "(set encoding to 'base64' for binary files). "
            "Parent directories are created automatically."
        ),
        parameters=[
            ToolParameter(
                name="path",
                description="Absolute path inside the sandbox where the file should be written.",
                required=True,
                schema={"type": "string"},
            ),
            ToolParameter(
                name="content",
                description="File content as a string.",
                required=True,
                schema={"type": "string"},
            ),
            ToolParameter(
                name="encoding",
                description="'utf-8' (default) for text, 'base64' for binary content.",
                required=False,
                schema={"type": "string", "enum": ["utf-8", "base64"], "default": "utf-8"},
            ),
        ],
    ),
    Tool(
        name="file_get",
        description=(
            "Download a file from the sandbox. Returns the file content "
            "as a UTF-8 string.  For binary files the content is "
            "base64-encoded and the result includes encoding='base64'."
        ),
        parameters=[
            ToolParameter(
                name="path",
                description="Absolute path inside the sandbox to read.",
                required=True,
                schema={"type": "string"},
            ),
        ],
    ),
]


class SandboxToolDriver(MCSToolDriver):
    """ToolDriver that wraps a :class:`SandboxPort` backend.

    Parameters
    ----------
    adapter : str
        Backend identifier.  Supported: ``"docker"``, ``"ssh"``.
    _adapter : SandboxPort | None
        Pre-built adapter instance (for testing / DI).
    **adapter_kwargs
        Forwarded to the adapter constructor when *_adapter* is None.
    """

    meta: DriverMeta = _SandboxToolDriverMeta()

    def __init__(
        self,
        *,
        adapter: str = "docker",
        _adapter: Optional[SandboxPort] = None,
        **adapter_kwargs: Any,
    ) -> None:
        if _adapter is not None:
            self._adapter: SandboxPort = _adapter
        elif adapter == "docker":
            from mcs.adapter.docker import DockerAdapter

            self._adapter = DockerAdapter(**adapter_kwargs)
        elif adapter == "ssh":
            from mcs.adapter.ssh import SSHAdapter

            self._adapter = SSHAdapter(**adapter_kwargs)
        else:
            raise ValueError(
                f"Unknown sandbox adapter: {adapter!r}. "
                f"Supported: 'docker', 'ssh'.  Or pass _adapter directly."
            )
        self._running = False
        self._sync_running_state()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _sync_running_state(self) -> None:
        """Query the adapter for the actual sandbox state.

        This handles the case where the backend (e.g. a Docker container)
        is already running from a previous session when the driver is
        instantiated.
        """
        try:
            result = self._adapter.status()
            self._running = result.get("running", False)
        except Exception:
            # If we can't reach the backend, assume stopped.
            self._running = False

    # ------------------------------------------------------------------
    # MCSToolDriver interface
    # ------------------------------------------------------------------

    def list_tools(self) -> List[Tool]:
        """Return available tools based on sandbox state.

        - **Stopped**: ``sandbox_start``, ``sandbox_status``
        - **Running**: ``sandbox_stop``, ``sandbox_status``,
          ``shell_exec``, ``file_put``, ``file_get``
        """
        if self._running:
            return [_TOOL_STOP, _TOOL_STATUS] + list(_RUNTIME_TOOLS)
        return [_TOOL_START, _TOOL_STATUS]

    def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """Dispatch a tool call to the appropriate adapter method."""
        # -- Lifecycle tools -----------------------------------------------
        if tool_name == "sandbox_start":
            result = self._adapter.start()
            self._running = result.get("running", False)
            logger.info("Sandbox started: %s", result)
            return json.dumps(result)

        if tool_name == "sandbox_stop":
            result = self._adapter.stop()
            self._running = False
            logger.info("Sandbox stopped: %s", result)
            return json.dumps(result)

        if tool_name == "sandbox_status":
            result = self._adapter.status()
            self._running = result.get("running", False)
            return json.dumps(result)

        # -- Runtime tools (require running sandbox) -----------------------
        if not self._running:
            return json.dumps({
                "error": "Sandbox is not running. Call sandbox_start first."
            })

        if tool_name == "shell_exec":
            command = arguments["command"]
            timeout = arguments.get("timeout", 30)
            result = self._adapter.exec(command, timeout=timeout)
            logger.info(
                "shell_exec [exit=%d]: %s", result.exit_code, command[:80]
            )
            return json.dumps({
                "exit_code": result.exit_code,
                "stdout": result.stdout,
                "stderr": result.stderr,
            })

        if tool_name == "file_put":
            path = arguments["path"]
            content_str = arguments["content"]
            encoding = arguments.get("encoding", "utf-8")
            if encoding == "base64":
                content_bytes = base64.b64decode(content_str)
            else:
                content_bytes = content_str.encode("utf-8")
            self._adapter.put_file(path, content_bytes)
            logger.info("file_put: %d bytes -> %s", len(content_bytes), path)
            return json.dumps({
                "path": path,
                "bytes_written": len(content_bytes),
            })

        if tool_name == "file_get":
            path = arguments["path"]
            raw = self._adapter.get_file(path)
            try:
                text = raw.decode("utf-8")
                return json.dumps({"path": path, "content": text, "encoding": "utf-8"})
            except UnicodeDecodeError:
                b64 = base64.b64encode(raw).decode("ascii")
                return json.dumps({"path": path, "content": b64, "encoding": "base64"})

        raise ValueError(f"Unknown tool: {tool_name}")
