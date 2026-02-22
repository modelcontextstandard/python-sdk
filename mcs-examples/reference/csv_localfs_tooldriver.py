from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import uuid4

from mcs.driver.core import DriverBinding, DriverMeta, MCSToolDriver, Tool, ToolParameter


@dataclass(frozen=True)
class _CsvLocalfsMeta(DriverMeta):
    id: str = "8f3c7a2e-9d4b-4f1a-b5e6-1c8a9f2d3e7b"
    name: str = "CSV LocalFS ToolDriver"
    version: str = "0.1.0"
    bindings: tuple[DriverBinding, ...] = (
        DriverBinding(protocol="CSV", transport="LocalFS", spec_format="JSON-Schema"),
    )
    supported_llms: tuple[str, ...] | None = None
    capabilities: tuple[str, ...] = ()


class CsvLocalfsToolDriver(MCSToolDriver):
    meta: DriverMeta = _CsvLocalfsMeta()

    def __init__(self, base_dir: str) -> None:
        self.base_dir = Path(base_dir).resolve()
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def list_tools(self) -> list[Tool]:
        return [
            Tool(
                name="list_csv_files",
                description="List all CSV files below the configured base directory.",
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

    def execute_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        if tool_name == "list_csv_files":
            return json.dumps(self._list_csv_files(), ensure_ascii=False)
        if tool_name == "read_csv_head":
            return json.dumps(
                self._read_csv_head(arguments["path"], int(arguments.get("limit", 5))),
                ensure_ascii=False,
            )
        if tool_name == "filter_csv_rows":
            return json.dumps(
                self._filter_csv_rows(
                    path=arguments["path"],
                    column=arguments["column"],
                    value=str(arguments["value"]),
                    limit=int(arguments.get("limit", 20)),
                ),
                ensure_ascii=False,
            )
        if tool_name == "summarize_numeric_column":
            return json.dumps(
                self._summarize_numeric_column(arguments["path"], arguments["column"]),
                ensure_ascii=False,
            )
        raise ValueError(f"Unknown tool: {tool_name}")

    def _resolve_csv_path(self, relative_path: str) -> Path:
        path = (self.base_dir / relative_path).resolve()
        if self.base_dir not in path.parents and path != self.base_dir:
            raise ValueError("Path escapes configured base directory.")
        if path.suffix.lower() != ".csv":
            raise ValueError("Only .csv files are allowed.")
        if not path.exists():
            raise FileNotFoundError(f"CSV file does not exist: {relative_path}")
        return path

    def _list_csv_files(self) -> list[str]:
        files = []
        for file_path in self.base_dir.rglob("*.csv"):
            files.append(str(file_path.relative_to(self.base_dir)))
        return sorted(files)

    def _read_csv_head(self, relative_path: str, limit: int) -> list[dict[str, str]]:
        path = self._resolve_csv_path(relative_path)
        rows: list[dict[str, str]] = []
        with path.open("r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            for i, row in enumerate(reader):
                if i >= max(0, limit):
                    break
                rows.append(dict(row))
        return rows

    def _filter_csv_rows(self, path: str, column: str, value: str, limit: int) -> list[dict[str, str]]:
        file_path = self._resolve_csv_path(path)
        matches: list[dict[str, str]] = []
        with file_path.open("r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if str(row.get(column, "")) == value:
                    matches.append(dict(row))
                    if len(matches) >= max(0, limit):
                        break
        return matches

    def _summarize_numeric_column(self, path: str, column: str) -> dict[str, float | int]:
        file_path = self._resolve_csv_path(path)
        values: list[float] = []
        with file_path.open("r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                raw = row.get(column)
                if raw is None or raw == "":
                    continue
                values.append(float(raw))
        if not values:
            raise ValueError(f"No numeric values found in column '{column}'.")
        return {
            "count": len(values),
            "min": min(values),
            "max": max(values),
            "avg": sum(values) / len(values),
        }
