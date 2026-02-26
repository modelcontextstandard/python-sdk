"""MCS ToolDriver for filesystem access.

Provides three tools: list_directory, read_file, write_file.
Delegates all I/O to the injected adapter so that the same driver
works with local disk, S3, SMB, or any other filesystem backend.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List

from mcs.driver.core import MCSToolDriver, Tool, ToolParameter, DriverMeta, DriverBinding

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class _FsToolDriverMeta(DriverMeta):
    id: str = "a1b2c3d4-fs01-4000-9000-filesystem0001"
    name: str = "Filesystem MCS ToolDriver"
    version: str = "0.2.0"
    bindings: tuple[DriverBinding, ...] = (
        DriverBinding(capability="filesystem", adapter="*", spec_format="Custom"),
    )
    supported_llms: None = None
    capabilities: tuple[str, ...] = ("orchestratable",)


_TOOLS = [
    Tool(
        name="list_directory",
        description="List files and subdirectories in a given directory path.",
        parameters=[
            ToolParameter(name="path", description="Absolute or relative directory path.", required=True),
        ],
    ),
    Tool(
        name="read_file",
        description="Read the text content of a file and return it.",
        parameters=[
            ToolParameter(name="path", description="Absolute or relative file path.", required=True),
            ToolParameter(name="encoding", description="Text encoding (default: utf-8).", required=False),
        ],
    ),
    Tool(
        name="write_file",
        description="Write text content to a file. Creates the file if it does not exist.",
        parameters=[
            ToolParameter(name="path", description="Absolute or relative file path.", required=True),
            ToolParameter(name="content", description="The text content to write.", required=True),
            ToolParameter(name="encoding", description="Text encoding (default: utf-8).", required=False),
        ],
    ),
]


class FilesystemToolDriver(MCSToolDriver):
    """Provides filesystem operations as structured tools for an orchestrator.

    Primary constructor takes an ``adapter`` flag (``"localfs"`` or
    ``"smb"``) and forwards ``**adapter_kwargs`` to the chosen adapter.
    For testing or alternative backends an existing adapter can be
    injected via ``_adapter``.
    """

    meta: DriverMeta = _FsToolDriverMeta()

    def __init__(
        self,
        *,
        adapter: str = "localfs",
        _adapter: Any = None,
        **adapter_kwargs: Any,
    ) -> None:
        if _adapter is not None:
            self._adapter = _adapter
        elif adapter == "smb":
            from mcs.adapter.smb import SmbAdapter
            self._adapter = SmbAdapter(**adapter_kwargs)
        else:
            from mcs.adapter.localfs import LocalFsAdapter
            self._adapter = LocalFsAdapter(**adapter_kwargs)

    # -- MCSToolDriver contract ----------------------------------------------

    def list_tools(self) -> List[Tool]:
        return list(_TOOLS)

    def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        if tool_name == "list_directory":
            return self._adapter.list_dir(arguments["path"])
        elif tool_name == "read_file":
            encoding = arguments.get("encoding", "utf-8")
            return self._adapter.read_text(arguments["path"], encoding=encoding)
        elif tool_name == "write_file":
            encoding = arguments.get("encoding", "utf-8")
            return self._adapter.write_text(
                arguments["path"], arguments["content"], encoding=encoding,
            )
        else:
            raise ValueError(f"Unknown tool: {tool_name}")
