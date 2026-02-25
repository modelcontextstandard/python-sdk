"""Tests for PromptStrategy and JsonPromptStrategy."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from mcs.driver.core import Tool, ToolParameter
from mcs.driver.core.prompt_strategy import (
    JsonPromptStrategy,
    PromptStrategy,
    UnknownToolBehavior,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_TOOLS = [
    Tool(
        name="addNumbers",
        description="Adds two numbers",
        parameters=[
            ToolParameter(name="a", description="first", required=True, schema={"type": "integer"}),
            ToolParameter(name="b", description="second", required=True, schema={"type": "integer"}),
        ],
    ),
    Tool(
        name="greet",
        description="Returns a greeting",
        parameters=[
            ToolParameter(name="name", description="whom to greet", required=True, schema={"type": "string"}),
        ],
    ),
]


@pytest.fixture
def strategy() -> JsonPromptStrategy:
    return JsonPromptStrategy.from_defaults()


# ---------------------------------------------------------------------------
# Factory / loading
# ---------------------------------------------------------------------------

class TestFactory:
    def test_default_returns_json_strategy(self):
        s = PromptStrategy.default()
        assert isinstance(s, JsonPromptStrategy)

    def test_from_defaults_loads_toml(self, strategy):
        assert "{tools}" in strategy.system_template
        assert "{call_example}" in strategy.system_template

    def test_from_toml_file(self, tmp_path):
        toml_content = textwrap.dedent("""\
            [system_message]
            template = "custom {tools} {call_example}"
            [call_example]
            example = "custom example"
            [parsing]
            tool_field_aliases = ["tool"]
            [retry_prompts]
            no_tool_field = "retry!"
            unknown_tool = "unknown {tool_name} {available}"
            execution_failed = "failed {tool_name} {error}"
        """)
        toml_file = tmp_path / "test.toml"
        toml_file.write_text(toml_content, encoding="utf-8")
        s = PromptStrategy.from_toml(str(toml_file))
        assert "custom" in s.system_template
        assert s.format_call_example() == "custom example"


# ---------------------------------------------------------------------------
# format_tools
# ---------------------------------------------------------------------------

class TestFormatTools:
    def test_produces_valid_json(self, strategy):
        output = strategy.format_tools(SAMPLE_TOOLS)
        schema = json.loads(output)
        assert "tools" in schema
        assert len(schema["tools"]) == 2

    def test_tool_names_present(self, strategy):
        schema = json.loads(strategy.format_tools(SAMPLE_TOOLS))
        names = {t["name"] for t in schema["tools"]}
        assert names == {"addNumbers", "greet"}

    def test_required_fields_present(self, strategy):
        schema = json.loads(strategy.format_tools(SAMPLE_TOOLS))
        add_tool = [t for t in schema["tools"] if t["name"] == "addNumbers"][0]
        assert "required" in add_tool["parameters"]
        assert set(add_tool["parameters"]["required"]) == {"a", "b"}

    def test_empty_tools(self, strategy):
        schema = json.loads(strategy.format_tools([]))
        assert schema["tools"] == []


# ---------------------------------------------------------------------------
# format_call_example
# ---------------------------------------------------------------------------

class TestFormatCallExample:
    def test_contains_tool_key(self, strategy):
        example = strategy.format_call_example()
        assert '"tool"' in example

    def test_contains_arguments_key(self, strategy):
        example = strategy.format_call_example()
        assert '"arguments"' in example


# ---------------------------------------------------------------------------
# parse_tool_call
# ---------------------------------------------------------------------------

class TestParseToolCall:
    def test_valid_json_tool_call(self, strategy):
        raw = json.dumps({"tool": "addNumbers", "arguments": {"a": 1, "b": 2}})
        result = strategy.parse_tool_call(raw)
        assert result is not None
        name, args = result
        assert name == "addNumbers"
        assert args == {"a": 1, "b": 2}

    def test_name_alias_accepted(self, strategy):
        raw = json.dumps({"name": "greet", "arguments": {"name": "World"}})
        result = strategy.parse_tool_call(raw)
        assert result is not None
        assert result[0] == "greet"

    def test_markdown_fence_healed(self, strategy):
        raw = '```json\n{"tool": "greet", "arguments": {"name": "X"}}\n```'
        result = strategy.parse_tool_call(raw)
        assert result is not None
        assert result[0] == "greet"

    def test_no_json_returns_none(self, strategy):
        assert strategy.parse_tool_call("Just some text") is None

    def test_json_without_tool_returns_none(self, strategy):
        raw = json.dumps({"arguments": {"a": 1}})
        assert strategy.parse_tool_call(raw) is None

    def test_invalid_json_returns_none(self, strategy):
        assert strategy.parse_tool_call('{"tool": "x", broken}') is None

    def test_empty_arguments_defaulted(self, strategy):
        raw = json.dumps({"tool": "addNumbers"})
        result = strategy.parse_tool_call(raw)
        assert result is not None
        assert result[1] == {}

    def test_surrounding_text_ignored(self, strategy):
        raw = 'Here is the call: {"tool": "greet", "arguments": {"name": "A"}} enjoy!'
        result = strategy.parse_tool_call(raw)
        assert result is not None
        assert result[0] == "greet"


# ---------------------------------------------------------------------------
# Retry prompts
# ---------------------------------------------------------------------------

class TestRetryPrompts:
    def test_retry_no_tool_field(self, strategy):
        msg = strategy.retry_no_tool_field()
        assert len(msg) > 0

    def test_retry_unknown_tool(self, strategy):
        msg = strategy.retry_unknown_tool("foo", "bar, baz")
        assert "foo" in msg
        assert "bar" in msg

    def test_retry_execution_failed(self, strategy):
        msg = strategy.retry_execution_failed("myTool", "timeout")
        assert "myTool" in msg
        assert "timeout" in msg


# ---------------------------------------------------------------------------
# UnknownToolBehavior
# ---------------------------------------------------------------------------

class TestUnknownToolBehavior:
    def test_default_is_silent(self, strategy):
        assert strategy.unknown_tool_behavior == UnknownToolBehavior.SILENT

    def test_can_set_retry(self):
        s = JsonPromptStrategy.from_defaults()
        s.unknown_tool_behavior = UnknownToolBehavior.RETRY_WITH_LIST
        assert s.unknown_tool_behavior == UnknownToolBehavior.RETRY_WITH_LIST
