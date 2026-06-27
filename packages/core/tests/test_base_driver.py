"""Tests for DriverBase -- the shared LLM-facing logic."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import pytest

from mcs.driver.core import (
    DriverBase,
    DriverMeta,
    DriverBinding,
    DriverResponse,
    Tool,
    ToolParameter,
    MCSToolDriver,
    PromptStrategy,
    JsonPromptStrategy,
    UnknownToolBehavior,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _TestMeta(DriverMeta):
    id: str = "test-0000"
    name: str = "Test Driver"
    version: str = "0.0.1"
    bindings: tuple[DriverBinding, ...] = ()
    supported_llms: tuple[str, ...] = ("*",)
    capabilities: tuple[str, ...] = ()


class ConcreteDriver(DriverBase):
    """Minimal concrete subclass for testing."""

    meta: DriverMeta = _TestMeta()

    def __init__(self, tools: list[Tool] | None = None, **kwargs: Any):
        super().__init__(**kwargs)
        self._tools = tools or []
        self._execute_result: Any = "ok"
        self._execute_error: Exception | None = None

    def list_tools(self) -> list[Tool]:
        return self._tools

    def execute_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        if self._execute_error is not None:
            raise self._execute_error
        return self._execute_result


TOOLS = [
    Tool(
        name="add",
        description="Adds numbers",
        parameters=[
            ToolParameter(name="a", description="first", required=True, schema={"type": "integer"}),
            ToolParameter(name="b", description="second", required=True, schema={"type": "integer"}),
        ],
    ),
]


@pytest.fixture
def driver() -> ConcreteDriver:
    return ConcreteDriver(tools=TOOLS)


# ---------------------------------------------------------------------------
# get_function_description
# ---------------------------------------------------------------------------

class TestGetFunctionDescription:
    def test_returns_json_schema(self, driver):
        desc = driver.get_function_description()
        schema = json.loads(desc)
        assert "tools" in schema
        assert schema["tools"][0]["name"] == "add"

    def test_custom_override(self):
        d = ConcreteDriver(tools=TOOLS, custom_tool_description="custom desc")
        assert d.get_function_description() == "custom desc"


# ---------------------------------------------------------------------------
# get_driver_system_message
# ---------------------------------------------------------------------------

class TestGetDriverSystemMessage:
    def test_contains_tools_and_example(self, driver):
        msg = driver.get_driver_system_message()
        assert "add" in msg
        assert '"tool"' in msg

    def test_custom_override(self):
        d = ConcreteDriver(
            tools=TOOLS,
            custom_system_message="my system prompt"
        )
        assert d.get_driver_system_message() == "my system prompt"


# ---------------------------------------------------------------------------
# process_llm_response
# ---------------------------------------------------------------------------

class TestProcessLlmResponse:
    def test_plain_text_returns_empty(self, driver):
        resp = driver.process_llm_response("Hello!")
        assert resp.call_executed is False
        assert resp.call_failed is False

    def test_valid_tool_call(self, driver):
        driver._execute_result = {"sum": 3}
        llm = json.dumps({"tool": "add", "arguments": {"a": 1, "b": 2}})
        resp = driver.process_llm_response(llm)
        assert resp.call_executed is True
        assert resp.tool_call_result is not None

    def test_markdown_fence_call(self, driver):
        driver._execute_result = "5"
        llm = '```json\n{"tool": "add", "arguments": {"a": 2, "b": 3}}\n```'
        resp = driver.process_llm_response(llm)
        assert resp.call_executed is True

    def test_unknown_tool_silent(self, driver):
        llm = json.dumps({"tool": "nonexistent", "arguments": {}})
        resp = driver.process_llm_response(llm)
        assert resp.call_executed is False
        assert resp.call_failed is False

    def test_unknown_tool_retry_with_list(self):
        strategy = JsonPromptStrategy.from_defaults()
        strategy.unknown_tool_behavior = UnknownToolBehavior.RETRY_WITH_LIST
        d = ConcreteDriver(tools=TOOLS, prompt_strategy=strategy)
        llm = json.dumps({"tool": "nonexistent", "arguments": {}})
        resp = d.process_llm_response(llm)
        assert resp.call_failed is True
        assert "nonexistent" in (resp.call_detail or "")
        assert resp.retry_prompt is not None
        assert "add" in resp.retry_prompt

    def test_execution_error(self, driver):
        driver._execute_error = RuntimeError("kaboom")
        llm = json.dumps({"tool": "add", "arguments": {"a": 1, "b": 2}})
        resp = driver.process_llm_response(llm)
        assert resp.call_failed is True
        assert "kaboom" in (resp.call_detail or "")
        assert resp.retry_prompt is not None

    def test_dict_input_handled(self, driver):
        driver._execute_result = "ok"
        resp = driver.process_llm_response({"tool": "add", "arguments": {"a": 1, "b": 2}})
        assert resp.call_executed is True

    def test_name_alias_works(self, driver):
        driver._execute_result = "ok"
        llm = json.dumps({"name": "add", "arguments": {"a": 1, "b": 2}})
        resp = driver.process_llm_response(llm)
        assert resp.call_executed is True

    def test_no_tool_field_returns_empty(self, driver):
        llm = json.dumps({"arguments": {"a": 1}})
        resp = driver.process_llm_response(llm)
        assert resp.call_executed is False
        assert resp.call_failed is False

    def test_result_in_messages(self, driver):
        driver._execute_result = {"sum": 7}
        llm = json.dumps({"tool": "add", "arguments": {"a": 3, "b": 4}})
        resp = driver.process_llm_response(llm)
        assert resp.messages is not None
        assert len(resp.messages) == 2
        assert resp.messages[0]["role"] == "assistant"
        assert resp.messages[1]["role"] == "system"
