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
# parse_tool_calls (all calls in one message)
# ---------------------------------------------------------------------------

class TestParseToolCalls:
    def test_finds_all_calls_in_one_text(self, strategy):
        raw = (
            "First the example:\n```json\n"
            '{"tool": "findCatsByTags", "arguments": {"tags": ["Mops"]}}\n```\n'
            "Then the real one:\n```json\n"
            '{"tool": "greet", "arguments": {"name": "Alice"}}\n```'
        )
        calls = strategy.parse_tool_calls(raw)
        assert [name for name, _args, _end in calls] == ["findCatsByTags", "greet"]
        assert calls[1][1] == {"name": "Alice"}

    def test_bare_json_pair_both_found(self, strategy):
        raw = '{"tool": "a", "arguments": {"x": 1}} then {"name": "b", "arguments": {}}'
        assert [n for n, _a, _e in strategy.parse_tool_calls(raw)] == ["a", "b"]

    def test_braces_inside_strings_do_not_split(self, strategy):
        raw = '{"tool": "a", "arguments": {"pattern": "a{b}c"}}'
        calls = strategy.parse_tool_calls(raw)
        assert [(n, a) for n, a, _e in calls] == [("a", {"pattern": "a{b}c"})]

    def test_non_call_objects_skipped(self, strategy):
        raw = '{"foo": "bar"} {"tool": "greet", "arguments": {}}'
        assert [n for n, _a, _e in strategy.parse_tool_calls(raw)] == ["greet"]

    def test_parse_tool_call_returns_first_of_many(self, strategy):
        raw = '{"tool": "a", "arguments": {}} and {"tool": "b", "arguments": {}}'
        assert strategy.parse_tool_call(raw)[0] == "a"

    def test_end_offset_covers_object_and_trailing_fence(self, strategy):
        raw = '```json\n{"tool": "greet", "arguments": {}}\n```'
        (_name, _args, end), = strategy.parse_tool_calls(raw)
        assert raw[:end].endswith("```")          # the closing fence is consumed too
        assert end == len(raw)

    def test_unbalanced_fence_defers(self, strategy):
        assert strategy.parse_tool_calls('```json\n{"tool": "a"') == []


# ---------------------------------------------------------------------------
# Retry prompts
# ---------------------------------------------------------------------------

class TestRetryPrompts:
    def test_retry_execution_failed(self, strategy):
        msg = strategy.retry_execution_failed("myTool", "timeout")
        assert "myTool" in msg
        assert "timeout" in msg
