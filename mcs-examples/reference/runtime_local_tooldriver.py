from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import uuid4

from mcs.driver.core import DriverBinding, DriverMeta, MCSToolDriver, Tool, ToolParameter


@dataclass(frozen=True)
class _RuntimeLocalMeta(DriverMeta):
    id: str = str(uuid4())
    name: str = "Runtime Local ToolDriver"
    version: str = "0.1.0"
    bindings: tuple[DriverBinding, ...] = (
        DriverBinding(protocol="Runtime", transport="LocalProcess", spec_format="JSON-Schema"),
    )
    supported_llms: tuple[str, ...] | None = None
    capabilities: tuple[str, ...] = ()


class RuntimeLocalToolDriver(MCSToolDriver):
    meta: DriverMeta = _RuntimeLocalMeta()

    def list_tools(self) -> list[Tool]:
        return [
            Tool(
                name="now_utc",
                description="Return current UTC timestamp in ISO-8601 format.",
                parameters=[],
            ),
            Tool(
                name="format_epoch_seconds",
                description="Convert epoch seconds to UTC ISO-8601 string.",
                parameters=[
                    ToolParameter(
                        name="epoch",
                        description="Unix epoch timestamp in seconds.",
                        required=True,
                        schema={"type": "number"},
                    )
                ],
            ),
        ]

    def execute_tool(self, tool_name: str, arguments: dict[str, object]) -> str:
        if tool_name == "now_utc":
            return json.dumps({"timestamp": datetime.now(timezone.utc).isoformat()})
        if tool_name == "format_epoch_seconds":
            epoch = float(arguments["epoch"])
            return json.dumps({"timestamp": datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()})
        raise ValueError(f"Unknown tool: {tool_name}")
