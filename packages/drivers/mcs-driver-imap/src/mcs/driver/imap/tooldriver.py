"""MCS ToolDriver for IMAP mailbox access.

Provides seven tools for reading, searching, and organising e-mail.
Delegates all I/O to the injected adapter so the same driver works
with any backend that satisfies ``ImapPort``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List

from mcs.driver.core import (
    DriverBinding,
    DriverMeta,
    MCSToolDriver,
    Tool,
    ToolParameter,
)

from .ports import ImapPort

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class _ImapToolDriverMeta(DriverMeta):
    id: str = "c4e8f1a2-imap-4001-9000-imaptooldrv001"
    name: str = "IMAP MCS ToolDriver"
    version: str = "0.1.0"
    bindings: tuple[DriverBinding, ...] = (
        DriverBinding(capability="imap", adapter="imap", spec_format="Custom"),
    )
    supported_llms: None = None
    capabilities: tuple[str, ...] = ("orchestratable",)


_TOOLS: list[Tool] = [
    Tool(
        name="list_folders",
        title="List mailbox folders",
        description="List all folders (mailboxes) available on the IMAP server.",
        parameters=[],
    ),
    Tool(
        name="list_messages",
        title="List messages in a folder",
        description=(
            "List message headers (subject, from, date, flags) in a folder, "
            "newest first.  Returns at most `limit` entries."
        ),
        parameters=[
            ToolParameter(
                name="folder",
                description="Folder name (default: INBOX).",
                required=False,
                schema={"type": "string", "default": "INBOX"},
            ),
            ToolParameter(
                name="limit",
                description="Maximum number of messages to return (default: 20).",
                required=False,
                schema={"type": "integer", "default": 20},
            ),
        ],
    ),
    Tool(
        name="fetch_message",
        title="Fetch a complete message",
        description=(
            "Fetch the full message identified by its UID, including body text."
        ),
        parameters=[
            ToolParameter(name="uid", description="Message UID.", required=True, schema={"type": "integer"}),
            ToolParameter(
                name="folder",
                description="Folder containing the message (default: INBOX).",
                required=False,
                schema={"type": "string", "default": "INBOX"},
            ),
        ],
    ),
    Tool(
        name="search_messages",
        title="Search messages by criteria",
        description=(
            "Search messages matching IMAP criteria such as "
            'FROM "alice", SUBJECT "invoice", UNSEEN, SINCE 01-Jan-2025, etc.'
        ),
        parameters=[
            ToolParameter(
                name="criteria",
                description='IMAP search criteria string (default: "ALL").',
                required=False,
                schema={"type": "string", "default": "ALL"},
            ),
            ToolParameter(
                name="folder",
                description="Folder to search in (default: INBOX).",
                required=False,
                schema={"type": "string", "default": "INBOX"},
            ),
            ToolParameter(
                name="limit",
                description="Maximum number of results (default: 20).",
                required=False,
                schema={"type": "integer", "default": 20},
            ),
        ],
    ),
    Tool(
        name="move_message",
        title="Move a message to another folder",
        description="Move a message from one folder to another (COPY + delete).",
        parameters=[
            ToolParameter(name="uid", description="Message UID.", required=True, schema={"type": "integer"}),
            ToolParameter(name="destination", description="Target folder name.", required=True, schema={"type": "string"}),
            ToolParameter(
                name="folder",
                description="Source folder (default: INBOX).",
                required=False,
                schema={"type": "string", "default": "INBOX"},
            ),
        ],
    ),
    Tool(
        name="set_flags",
        title="Set or remove message flags",
        description=(
            r"Add or remove IMAP flags on a message.  Common flags: "
            r"\Seen, \Flagged, \Answered, \Deleted."
        ),
        parameters=[
            ToolParameter(name="uid", description="Message UID.", required=True, schema={"type": "integer"}),
            ToolParameter(
                name="flags",
                description=r"Space-separated flags, e.g. '\Seen \Flagged'.",
                required=True,
                schema={"type": "string"},
            ),
            ToolParameter(
                name="remove",
                description="If true, remove the flags instead of adding them (default: false).",
                required=False,
                schema={"type": "boolean", "default": False},
            ),
            ToolParameter(
                name="folder",
                description="Folder containing the message (default: INBOX).",
                required=False,
                schema={"type": "string", "default": "INBOX"},
            ),
        ],
    ),
    Tool(
        name="create_folder",
        title="Create a new mailbox folder",
        description="Create a new folder on the IMAP server for organising mail.",
        parameters=[
            ToolParameter(name="name", description="Name of the folder to create.", required=True, schema={"type": "string"}),
        ],
    ),
]


class ImapToolDriver(MCSToolDriver):
    """Provides IMAP mailbox operations as structured tools.

    The adapter can be injected via ``_adapter`` for testing.
    Otherwise, supply IMAP connection parameters and the default
    ``ImapAdapter`` from ``mcs-adapter-imap`` will be used.
    """

    meta: DriverMeta = _ImapToolDriverMeta()

    def __init__(
        self,
        *,
        host: str | None = None,
        user: str | None = None,
        password: str | None = None,
        port: int | None = None,
        ssl: bool = True,
        starttls: bool = False,
        _adapter: ImapPort | None = None,
    ) -> None:
        if _adapter is not None:
            self._adapter: ImapPort = _adapter
        else:
            if not all([host, user, password]):
                raise ValueError("host, user, and password are required when no _adapter is injected")
            from mcs.adapter.imap import ImapAdapter

            self._adapter = ImapAdapter(
                host=host,  # type: ignore[arg-type]
                user=user,  # type: ignore[arg-type]
                password=password,  # type: ignore[arg-type]
                port=port,
                ssl=ssl,
                starttls=starttls,
            )

    def list_tools(self) -> List[Tool]:
        return list(_TOOLS)

    def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        if tool_name == "list_folders":
            return self._adapter.list_folders()

        if tool_name == "list_messages":
            return self._adapter.list_messages(
                folder=arguments.get("folder", "INBOX"),
                limit=int(arguments.get("limit", 20)),
            )

        if tool_name == "fetch_message":
            return self._adapter.fetch_message(
                uid=int(arguments["uid"]),
                folder=arguments.get("folder", "INBOX"),
            )

        if tool_name == "search_messages":
            return self._adapter.search_messages(
                criteria=arguments.get("criteria", "ALL"),
                folder=arguments.get("folder", "INBOX"),
                limit=int(arguments.get("limit", 20)),
            )

        if tool_name == "move_message":
            return self._adapter.move_message(
                uid=int(arguments["uid"]),
                destination=arguments["destination"],
                folder=arguments.get("folder", "INBOX"),
            )

        if tool_name == "set_flags":
            return self._adapter.set_flags(
                uid=int(arguments["uid"]),
                flags=arguments["flags"],
                remove=bool(arguments.get("remove", False)),
                folder=arguments.get("folder", "INBOX"),
            )

        if tool_name == "create_folder":
            return self._adapter.create_folder(name=arguments["name"])

        raise ValueError(f"Unknown tool: {tool_name}")
