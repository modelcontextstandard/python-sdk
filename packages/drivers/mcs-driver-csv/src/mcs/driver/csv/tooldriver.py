"""MCS ToolDriver for CSV file access.

Provides tools for listing, reading, filtering, and summarizing CSV
files.  Delegates all filesystem I/O to the injected adapter so that
the same driver works with local disk, S3, SMB, or any other backend.

Ported from ``mcs-examples/reference/csv_tooldriver.py``.
"""

from __future__ import annotations

import csv
import io
import json
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

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class _CsvToolDriverMeta(DriverMeta):
    id: str = "8f3c7a2e-9d4b-4f1a-b5e6-1c8a9f2d3e7b"
    name: str = "CSV ToolDriver"
    version: str = "0.1.0"
    bindings: tuple[DriverBinding, ...] = (
        DriverBinding(capability="csv", adapter="*", spec_format="Custom"),
    )
    supported_llms: None = None
    capabilities: tuple[str, ...] = ("orchestratable",)


_TOOLS = [
    Tool(
        name="list_csv_files",
        description="List all CSV files available in the configured data source.",
        parameters=[],
    ),
    Tool(
        name="read_csv_head",
        description="Read first N rows from a CSV file and return them as JSON records.",
        parameters=[
            ToolParameter("path", "Relative path to CSV file", required=True, schema={"type": "string"}),
            ToolParameter("limit", "Maximum number of rows", schema={"type": "integer", "default": 5}),
        ],
    ),
    Tool(
        name="filter_csv_rows",
        description="Filter rows where one column equals a specific value.",
        parameters=[
            ToolParameter("path", "Relative path to CSV file", required=True, schema={"type": "string"}),
            ToolParameter("column", "Column name", required=True, schema={"type": "string"}),
            ToolParameter("value", "Expected column value", required=True, schema={"type": "string"}),
            ToolParameter("limit", "Maximum number of matches", schema={"type": "integer", "default": 20}),
        ],
    ),
    Tool(
        name="summarize_numeric_column",
        description="Compute count, min, max, and average for a numeric CSV column.",
        parameters=[
            ToolParameter("path", "Relative path to CSV file", required=True, schema={"type": "string"}),
            ToolParameter("column", "Numeric column name", required=True, schema={"type": "string"}),
        ],
    ),
]


class CsvToolDriver(MCSToolDriver):
    """Provides CSV analysis operations as structured tools.

    Primary constructor takes a ``base_dir`` parameter and creates a
    ``LocalFsAdapter`` internally.  For testing or alternative backends
    an existing adapter can be injected via ``_adapter``.
    """

    meta: DriverMeta = _CsvToolDriverMeta()

    def __init__(
        self,
        *,
        base_dir: str | None = None,
        _adapter: Any = None,
    ) -> None:
        if _adapter is not None:
            self._adapter = _adapter
        else:
            from mcs.adapter.localfs import LocalFsAdapter
            self._adapter = LocalFsAdapter(base_dir=base_dir)

    # -- MCSToolDriver contract -----------------------------------------------

    def list_tools(self) -> List[Tool]:
        return list(_TOOLS)

    def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        dispatch = {
            "list_csv_files": lambda: self._list_csv_files(),
            "read_csv_head": lambda: self._read_csv_head(
                arguments["path"], int(arguments.get("limit", 5)),
            ),
            "filter_csv_rows": lambda: self._filter_csv_rows(
                arguments["path"],
                arguments["column"],
                str(arguments["value"]),
                int(arguments.get("limit", 20)),
            ),
            "summarize_numeric_column": lambda: self._summarize_column(
                arguments["path"], arguments["column"],
            ),
        }
        handler = dispatch.get(tool_name)
        if handler is None:
            raise ValueError(f"Unknown tool: {tool_name}")
        return json.dumps(handler(), ensure_ascii=False)

    # -- CSV-specific logic (adapter for I/O only) ----------------------------

    def _list_csv_files(self) -> list[str]:
        return self._adapter.list_files(".", "*.csv")

    def _read_rows(self, path: str) -> list[dict[str, str]]:
        text = self._adapter.read_raw(path)
        return list(csv.DictReader(io.StringIO(text)))

    def _read_csv_head(self, path: str, limit: int) -> list[dict[str, str]]:
        return self._read_rows(path)[:max(0, limit)]

    def _filter_csv_rows(
        self, path: str, column: str, value: str, limit: int,
    ) -> list[dict[str, str]]:
        matches: list[dict[str, str]] = []
        for row in self._read_rows(path):
            if str(row.get(column, "")) == value:
                matches.append(row)
                if len(matches) >= max(0, limit):
                    break
        return matches

    def _summarize_column(self, path: str, column: str) -> dict[str, float | int]:
        values = [float(r[column]) for r in self._read_rows(path) if r.get(column)]
        if not values:
            raise ValueError(f"No numeric values found in column '{column}'.")
        return {
            "count": len(values),
            "min": min(values),
            "max": max(values),
            "avg": sum(values) / len(values),
        }
