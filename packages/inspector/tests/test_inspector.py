"""Tests for the generic MCS Inspector core."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List
from unittest.mock import patch

import pytest

from mcs.driver.core import MCSToolDriver, Tool, ToolParameter, DriverMeta, DriverBinding
from mcs.inspector.core import (
    ExtraColumn,
    _build_overview_table,
    _show_tool_detail,
    _prompt_arguments,
)


@dataclass(frozen=True)
class _TestMeta(DriverMeta):
    id: str = "test-0001"
    name: str = "Test ToolDriver"
    version: str = "0.0.1"
    bindings: tuple[DriverBinding, ...] = ()
    supported_llms: None = None
    capabilities: tuple[str, ...] = ()


_TOOLS = [
    Tool(
        name="greet",
        title="Say hello",
        description="Greet a person by name.",
        parameters=[
            ToolParameter(name="name", description="Person's name", required=True, schema={"type": "string"}),
            ToolParameter(name="loud", description="Shout?", required=False, schema={"type": "boolean", "default": False}),
        ],
    ),
    Tool(
        name="add",
        title="Add two numbers",
        description="Compute a + b.",
        parameters=[
            ToolParameter(name="a", description="First number", required=True, schema={"type": "integer"}),
            ToolParameter(name="b", description="Second number", required=True, schema={"type": "integer"}),
        ],
    ),
    Tool(
        name="ping",
        title="Ping",
        description="Returns pong.",
        parameters=[],
    ),
]


class FakeToolDriver(MCSToolDriver):
    meta = _TestMeta()

    def list_tools(self) -> List[Tool]:
        return list(_TOOLS)

    def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        if tool_name == "greet":
            name = arguments.get("name", "World")
            loud = arguments.get("loud", False)
            msg = f"Hello, {name}!"
            return json.dumps({"message": msg.upper() if loud else msg})
        if tool_name == "add":
            return json.dumps({"result": int(arguments["a"]) + int(arguments["b"])})
        if tool_name == "ping":
            return json.dumps({"response": "pong"})
        raise ValueError(f"Unknown tool: {tool_name}")


@pytest.fixture()
def td() -> FakeToolDriver:
    return FakeToolDriver()


class TestBuildOverviewTable:

    def test_table_has_correct_row_count(self, td):
        table = _build_overview_table(td, title="Test")
        assert table.row_count == 3

    def test_table_title_contains_count(self, td):
        table = _build_overview_table(td, title="Test")
        assert "3 tools" in table.title

    def test_extra_columns_appear(self, td):
        extra = [ExtraColumn(header="Kind", value_fn=lambda t, i: "custom")]
        table = _build_overview_table(td, title="Test", extra_columns=extra)
        col_names = [c.header for c in table.columns]
        assert "Kind" in col_names


class TestShowToolDetail:

    def test_does_not_crash_on_valid_tool(self, td, capsys):
        _show_tool_detail(td, "greet")

    def test_prints_error_for_unknown_tool(self, td, capsys):
        _show_tool_detail(td, "nonexistent")


class TestPromptArguments:

    def test_uses_defaults_on_empty_input(self):
        tool = _TOOLS[0]  # greet: name(required), loud(default=False)
        with patch("mcs.inspector.core.console") as mock_console:
            mock_console.input = lambda prompt: ""
            args = _prompt_arguments(tool)
        assert args.get("loud") is False

    def test_parses_integer(self):
        tool = _TOOLS[1]  # add: a(int), b(int)
        inputs = iter(["42", "8"])
        with patch("mcs.inspector.core.console") as mock_console:
            mock_console.input = lambda prompt: next(inputs)
            mock_console.print = lambda *a, **kw: None
            args = _prompt_arguments(tool)
        assert args["a"] == 42
        assert args["b"] == 8

    def test_parses_boolean(self):
        tool = _TOOLS[0]  # greet
        inputs = iter(["Alice", "true"])
        with patch("mcs.inspector.core.console") as mock_console:
            mock_console.input = lambda prompt: next(inputs)
            mock_console.print = lambda *a, **kw: None
            args = _prompt_arguments(tool)
        assert args["name"] == "Alice"
        assert args["loud"] is True

    def test_empty_params_returns_empty_dict(self):
        tool = _TOOLS[2]  # ping: no params
        args = _prompt_arguments(tool)
        assert args == {}


class TestExecuteTool:

    def test_greet_execution(self, td):
        result = json.loads(td.execute_tool("greet", {"name": "Danny"}))
        assert result["message"] == "Hello, Danny!"

    def test_add_execution(self, td):
        result = json.loads(td.execute_tool("add", {"a": 3, "b": 7}))
        assert result["result"] == 10

    def test_ping_execution(self, td):
        result = json.loads(td.execute_tool("ping", {}))
        assert result["response"] == "pong"


class TestCLIParsing:

    def test_main_module_parses_mailread_subcommand(self):
        from mcs.inspector.mailread_cli import add_parser
        import argparse
        p = argparse.ArgumentParser()
        sub = p.add_subparsers(dest="driver")
        add_parser(sub)
        args = p.parse_args(["mailread", "--host", "mail.test", "--user", "me"])
        assert args.host == "mail.test"
        assert args.user == "me"
        assert args.driver == "mailread"

    def test_main_module_parses_rest_subcommand(self):
        from mcs.inspector.rest_cli import add_parser
        import argparse
        p = argparse.ArgumentParser()
        sub = p.add_subparsers(dest="driver")
        add_parser(sub)
        args = p.parse_args(["rest", "https://example.com/api.json", "--include-tags", "users"])
        assert args.url == "https://example.com/api.json"
        assert args.include_tags == ["users"]
        assert args.driver == "rest"
