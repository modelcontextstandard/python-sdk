"""Tests for ExtractionStrategy implementations and DriverBase extraction chain."""

from __future__ import annotations

import json
from typing import Any
from dataclasses import dataclass

import pytest

from mcs.driver.core import (
    DriverBase,
    MCSToolDriver,
    Tool,
    ToolParameter,
    DriverMeta,
    DriverBinding,
    JsonPromptStrategy,
)
from mcs.driver.core.extraction_strategy import (
    ExtractionStrategy,
    TextExtractionStrategy,
    DirectDictExtractionStrategy,
    OpenAIExtractionStrategy,
)


# -- Helpers ------------------------------------------------------------------

@dataclass(frozen=True)
class _FakeMeta(DriverMeta):
    id: str = "fake-0001"
    name: str = "Fake"
    version: str = "0.1.0"
    bindings: tuple[DriverBinding, ...] = ()
    supported_llms: None = None
    capabilities: tuple[str, ...] = ()


class FakeToolDriver(MCSToolDriver):
    meta: DriverMeta = _FakeMeta()

    def __init__(self, tools: list[Tool], results: dict[str, str] | None = None):
        self._tools = tools
        self._results = results or {}

    def list_tools(self) -> list[Tool]:
        return self._tools

    def execute_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        return self._results.get(tool_name, f"executed:{tool_name}")


TOOL_A = Tool(name="greet", description="Greet someone", parameters=[
    ToolParameter(name="name", description="Who to greet", required=True),
])


class SimpleDriverBase(DriverBase):
    meta: DriverMeta = _FakeMeta()

    def __init__(self, **kwargs: Any):
        super().__init__(**kwargs)
        self._td = FakeToolDriver([TOOL_A], {"greet": "Hello!"})

    def list_tools(self) -> list[Tool]:
        return self._td.list_tools()

    def execute_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        return self._td.execute_tool(tool_name, arguments)


# -- TextExtractionStrategy ---------------------------------------------------

class TestTextExtractionStrategy:
    def setup_method(self):
        self.codec = JsonPromptStrategy.from_defaults()
        self.strategy = TextExtractionStrategy(self.codec)

    def test_extracts_json_from_text(self):
        text = 'Sure! {"tool": "greet", "arguments": {"name": "Alice"}}'
        result = self.strategy.extract(text)
        assert result is not None
        assert result[0] == "greet"
        assert result[1] == {"name": "Alice"}

    def test_returns_none_for_dict_input(self):
        assert self.strategy.extract({"tool": "greet"}) is None

    def test_returns_none_for_no_json(self):
        assert self.strategy.extract("Just a regular message.") is None

    def test_returns_none_for_invalid_json(self):
        assert self.strategy.extract("Here: {broken json}}") is None

    def test_returns_none_for_json_without_tool(self):
        assert self.strategy.extract('{"foo": "bar"}') is None


# -- DirectDictExtractionStrategy ---------------------------------------------

class TestDirectDictExtractionStrategy:
    def setup_method(self):
        self.strategy = DirectDictExtractionStrategy()

    def test_extracts_tool_field(self):
        result = self.strategy.extract({"tool": "greet", "arguments": {"name": "Bob"}})
        assert result == ("greet", {"name": "Bob"})

    def test_extracts_name_alias(self):
        result = self.strategy.extract({"name": "greet", "arguments": {}})
        assert result == ("greet", {})

    def test_returns_none_for_str_input(self):
        assert self.strategy.extract("not a dict") is None

    def test_returns_none_for_missing_tool_key(self):
        assert self.strategy.extract({"arguments": {"x": 1}}) is None

    def test_returns_none_for_empty_dict(self):
        assert self.strategy.extract({}) is None

    def test_handles_arguments_as_json_string(self):
        result = self.strategy.extract({
            "tool": "greet",
            "arguments": '{"name": "Charlie"}',
        })
        assert result == ("greet", {"name": "Charlie"})

    def test_handles_missing_arguments(self):
        result = self.strategy.extract({"tool": "greet"})
        assert result == ("greet", {})


# -- OpenAIExtractionStrategy -------------------------------------------------

class TestOpenAIExtractionStrategy:
    def setup_method(self):
        self.strategy = OpenAIExtractionStrategy()

    def test_extracts_openai_format(self):
        payload = {
            "tool_calls": [{
                "id": "call_123",
                "function": {
                    "name": "greet",
                    "arguments": '{"name": "Dana"}',
                },
            }],
        }
        result = self.strategy.extract(payload)
        assert result == ("greet", {"name": "Dana"})

    def test_handles_dict_arguments(self):
        payload = {
            "tool_calls": [{
                "function": {
                    "name": "greet",
                    "arguments": {"name": "Eve"},
                },
            }],
        }
        result = self.strategy.extract(payload)
        assert result == ("greet", {"name": "Eve"})

    def test_returns_none_for_str_input(self):
        assert self.strategy.extract("not a dict") is None

    def test_returns_none_for_missing_tool_calls(self):
        assert self.strategy.extract({"content": "hello"}) is None

    def test_returns_none_for_empty_tool_calls(self):
        assert self.strategy.extract({"tool_calls": []}) is None

    def test_returns_none_for_missing_function(self):
        assert self.strategy.extract({"tool_calls": [{"id": "x"}]}) is None

    def test_returns_none_for_missing_name(self):
        payload = {"tool_calls": [{"function": {"arguments": "{}"}}]}
        assert self.strategy.extract(payload) is None

    def test_handles_invalid_arguments_json(self):
        payload = {
            "tool_calls": [{
                "function": {
                    "name": "greet",
                    "arguments": "{broken",
                },
            }],
        }
        result = self.strategy.extract(payload)
        assert result == ("greet", {})

    def test_returns_none_for_direct_dict_format(self):
        assert self.strategy.extract({"tool": "greet", "arguments": {}}) is None


# -- DriverBase extraction chain ----------------------------------------------

class TestDriverBaseExtractionChain:
    def test_str_input_uses_text_strategy(self):
        driver = SimpleDriverBase()
        dr = driver.process_llm_response('{"tool": "greet", "arguments": {"name": "X"}}')
        assert dr.call_executed is True
        assert dr.tool_call_result == "Hello!"

    def test_direct_dict_input(self):
        driver = SimpleDriverBase()
        dr = driver.process_llm_response({"tool": "greet", "arguments": {"name": "Y"}})
        assert dr.call_executed is True
        assert dr.tool_call_result == "Hello!"

    def test_openai_dict_input(self):
        driver = SimpleDriverBase()
        payload = {
            "tool_calls": [{
                "function": {
                    "name": "greet",
                    "arguments": '{"name": "Z"}',
                },
            }],
        }
        dr = driver.process_llm_response(payload)
        assert dr.call_executed is True
        assert dr.tool_call_result == "Hello!"

    def test_no_tool_call_in_text(self):
        driver = SimpleDriverBase()
        dr = driver.process_llm_response("Just chatting, no tool call here.")
        assert dr.call_executed is False
        assert dr.call_failed is False

    def test_no_tool_call_in_dict(self):
        driver = SimpleDriverBase()
        dr = driver.process_llm_response({"random": "data"})
        assert dr.call_executed is False
        assert dr.call_failed is False

    def test_unknown_tool_with_retry_behavior(self):
        from mcs.driver.core.prompt_strategy import UnknownToolBehavior
        ps = JsonPromptStrategy.from_defaults()
        ps.unknown_tool_behavior = UnknownToolBehavior.RETRY_WITH_LIST
        driver = SimpleDriverBase(prompt_strategy=ps)
        dr = driver.process_llm_response('{"tool": "nonexistent", "arguments": {}}')
        assert dr.call_failed is True
        assert "nonexistent" in (dr.call_detail or "")

    def test_unknown_tool_silent_returns_empty(self):
        driver = SimpleDriverBase()
        dr = driver.process_llm_response('{"tool": "nonexistent", "arguments": {}}')
        assert dr.call_executed is False
        assert dr.call_failed is False


# -- Caching ------------------------------------------------------------------

class TestExtractionCaching:
    def test_preferred_extractor_cached_after_first_hit(self):
        driver = SimpleDriverBase()
        assert driver._preferred_extractor is None

        driver.process_llm_response({"tool": "greet", "arguments": {}})
        assert isinstance(driver._preferred_extractor, DirectDictExtractionStrategy)

    def test_cached_strategy_tried_first(self):
        driver = SimpleDriverBase()

        driver.process_llm_response({"tool": "greet", "arguments": {}})
        assert isinstance(driver._preferred_extractor, DirectDictExtractionStrategy)

        driver.process_llm_response({"tool": "greet", "arguments": {}})
        assert isinstance(driver._preferred_extractor, DirectDictExtractionStrategy)

    def test_cache_switches_on_different_type(self):
        driver = SimpleDriverBase()

        driver.process_llm_response({"tool": "greet", "arguments": {}})
        assert isinstance(driver._preferred_extractor, DirectDictExtractionStrategy)

        driver.process_llm_response('{"tool": "greet", "arguments": {}}')
        assert isinstance(driver._preferred_extractor, TextExtractionStrategy)


# -- Custom ExtractionStrategy injection --------------------------------------

class TestCustomExtractionStrategy:
    def test_custom_strategy_used(self):
        class AlwaysGreetStrategy(ExtractionStrategy):
            def extract(self, llm_response):
                return ("greet", {"name": "Custom"})

        driver = SimpleDriverBase(
            _extraction_strategies=[AlwaysGreetStrategy()],
        )
        dr = driver.process_llm_response("anything at all")
        assert dr.call_executed is True
        assert dr.tool_call_result == "Hello!"
