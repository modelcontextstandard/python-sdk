"""Tests for ExtractionStrategy implementations and BaseDriver extraction chain."""

from __future__ import annotations

import json
from typing import Any
from dataclasses import dataclass

import pytest

from mcs.driver.core import (
    BaseDriver,
    MCSToolDriver,
    Tool,
    ToolParameter,
    DriverMeta,
    DriverBinding,
    JsonPromptStrategy,
)
from mcs.driver.core.extraction_strategy import (
    ExtractionStrategy,
    ExtractedCall,
    TextExtractionStrategy,
    OpenAICompletionExtractionStrategy,
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


class SimpleBaseDriver(BaseDriver):
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
        assert result == [ExtractedCall("greet", {"name": "Alice"})]

    def test_returns_empty_for_dict_input(self):
        assert self.strategy.extract({"tool": "greet"}) == []

    def test_returns_empty_for_no_json(self):
        assert self.strategy.extract("Just a regular message.") == []

    def test_returns_empty_for_invalid_json(self):
        assert self.strategy.extract("Here: {broken json}}") == []

    def test_returns_empty_for_json_without_tool(self):
        assert self.strategy.extract('{"foo": "bar"}') == []


# -- OpenAICompletionExtractionStrategy -------------------------------------------------

class TestOpenAICompletionExtractionStrategy:
    def setup_method(self):
        self.strategy = OpenAICompletionExtractionStrategy()

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
        assert result == [ExtractedCall("greet", {"name": "Dana"}, id="call_123")]

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
        assert result == [ExtractedCall("greet", {"name": "Eve"})]

    def test_extracts_all_parallel_calls(self):
        """A native batch yields one ExtractedCall per tool_call, in order."""
        payload = {
            "tool_calls": [
                {"id": "c1", "function": {"name": "greet", "arguments": '{"name": "A"}'}},
                {"id": "c2", "function": {"name": "greet", "arguments": '{"name": "B"}'}},
            ],
        }
        assert self.strategy.extract(payload) == [
            ExtractedCall("greet", {"name": "A"}, id="c1"),
            ExtractedCall("greet", {"name": "B"}, id="c2"),
        ]

    def test_returns_empty_for_str_input(self):
        assert self.strategy.extract("not a dict") == []

    def test_returns_empty_for_missing_tool_calls(self):
        assert self.strategy.extract({"content": "hello"}) == []

    def test_returns_empty_for_empty_tool_calls(self):
        assert self.strategy.extract({"tool_calls": []}) == []

    def test_returns_empty_for_missing_function(self):
        assert self.strategy.extract({"tool_calls": [{"id": "x"}]}) == []

    def test_returns_empty_for_missing_name(self):
        payload = {"tool_calls": [{"function": {"arguments": "{}"}}]}
        assert self.strategy.extract(payload) == []

    def test_incomplete_or_broken_arguments_are_omitted(self):
        """Non-empty but unparseable arguments -> the call is omitted (not runnable).

        Lets the driver keep buffering while streaming, or skip/heal otherwise,
        rather than executing with silently-dropped args.
        """
        payload = {
            "tool_calls": [{
                "function": {
                    "name": "greet",
                    "arguments": "{broken",
                },
            }],
        }
        assert self.strategy.extract(payload) == []

    def test_returns_empty_for_direct_dict_format(self):
        assert self.strategy.extract({"tool": "greet", "arguments": {}}) == []


# -- Codec call detection (looks_like_call, drives text recognizes) -----------

class TestLooksLikeCall:
    """The codec's marker detector used by the text strategy's ``recognizes``: does
    the (partial or complete) text look like a call in this codec's format?

    It starts conservatively (only a real marker) and releases fast -- a non-tool
    JSON, a foreign fence language, or plain prose must NOT be claimed.
    """

    def setup_method(self):
        self.codec = JsonPromptStrategy.from_defaults()

    def _f(self, text):
        return self.codec.looks_like_call(text)

    def test_bare_brace_with_tool_name(self):
        assert self._f('{"tool": "greet"') is True

    def test_name_alias_works(self):
        assert self._f('{"name": "greet"') is True

    def test_name_not_yet_streamed_still_claims(self):
        assert self._f('{"tool": "gr') is True

    def test_lone_brace_prefixes_claim(self):
        assert self._f("{") is True
        assert self._f('{"') is True

    def test_non_tool_json_is_released(self):
        assert self._f('{"foo": "bar"') is False

    def test_brace_without_string_key_is_released(self):
        assert self._f("{123") is False
        assert self._f("{ nope") is False

    def test_prose_brace_is_released(self):
        assert self._f("Use {x} in your code") is False

    def test_plain_prose_is_not_a_call(self):
        assert self._f("Just a normal answer.") is False

    def test_json_fence_claims(self):
        assert self._f("```json\n") is True
        assert self._f('```json\n{"tool": "greet"') is True

    def test_bare_fence_claims(self):
        assert self._f("```\n") is True

    def test_foreign_fence_language_is_released(self):
        assert self._f("```python\nprint(1)") is False
        assert self._f("```bash\nls -la") is False

    def test_complete_call_still_claims(self):
        # A complete call is claimed too (recognizes covers forming *and* complete).
        assert self._f('{"tool": "greet", "arguments": {"name": "A"}}') is True


# -- BaseDriver extraction chain ----------------------------------------------

class TestBaseDriverExtractionChain:
    def test_str_input_uses_text_strategy(self):
        driver = SimpleBaseDriver()
        dr = driver.process_llm_response('{"tool": "greet", "arguments": {"name": "X"}}')
        assert dr.call_executed is True
        assert dr.executed_calls[0].result == "Hello!"

    def test_openai_dict_input(self):
        driver = SimpleBaseDriver()
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
        assert dr.executed_calls[0].result == "Hello!"

    def test_no_tool_call_in_text(self):
        driver = SimpleBaseDriver()
        dr = driver.process_llm_response("Just chatting, no tool call here.")
        assert dr.call_executed is False
        assert dr.call_failed is False

    def test_no_tool_call_in_dict(self):
        driver = SimpleBaseDriver()
        dr = driver.process_llm_response({"random": "data"})
        assert dr.call_executed is False
        assert dr.call_failed is False

    def test_whole_text_example_then_real_call_runs_the_real_one(self):
        """A complete message that narrates an (unowned) example call and then makes the
        real (owned) one: the real call is found and executed -- not shadowed by the
        first. This is the non-streaming counterpart of the multi-call-in-text case."""
        driver = SimpleBaseDriver()                       # owns only greet
        text = (
            'Example: ```json\n'
            '{"tool": "findCatsByTags", "arguments": {"tags": ["x"]}}\n```\n'
            'Real: ```json\n{"tool": "greet", "arguments": {"name": "Bob"}}\n```'
        )
        dr = driver.process_llm_response(text)
        assert dr.call_executed is True
        assert dr.executed_calls[0].result == "Hello!"
        assert [r.name for r in dr.executed_calls] == ["greet"]   # only the owned one ran


# -- Custom ExtractionStrategy injection --------------------------------------

class TestCustomExtractionStrategy:
    def test_custom_strategy_with_recognizes(self):
        class AlwaysGreetStrategy(ExtractionStrategy):
            def recognizes(self, llm_response: str | dict) -> bool:
                return True

            def extract(self, llm_response):
                return [ExtractedCall("greet", {"name": "Custom"})]

        driver = SimpleBaseDriver(
            _extraction_strategies=[AlwaysGreetStrategy()],
        )
        dr = driver.process_llm_response("anything at all")
        assert dr.call_executed is True
        assert dr.executed_calls[0].result == "Hello!"


# -- Recognise-phase tests ---------------------------------------------------

class TestRecognizePhase:
    """Verify the recognise → extract protocol (native by envelope, text by content)."""

    def test_openai_recognizes_dict_with_tool_calls_key(self):
        s = OpenAICompletionExtractionStrategy()
        assert s.recognizes({"tool_calls": [{"function": {"name": "x", "arguments": "{}"}}]})

    def test_openai_recognizes_dict_with_tool_calls_none(self):
        """Even tool_calls=None means 'my format, no tool call'."""
        s = OpenAICompletionExtractionStrategy()
        assert s.recognizes({"role": "assistant", "content": "hi", "tool_calls": None})

    def test_openai_does_not_recognize_dict_without_tool_calls(self):
        s = OpenAICompletionExtractionStrategy()
        assert not s.recognizes({"role": "assistant", "content": "hi"})

    def test_openai_does_not_recognize_str(self):
        s = OpenAICompletionExtractionStrategy()
        assert not s.recognizes('{"tool_calls": []}')

    def test_text_recognizes_any_plain_text(self):
        """recognize = format ID: the text strategy owns any plain-text shape (a ``str``
        or ``{content: <str>}``) whether or not a call is embedded. A block/item list or
        an envelope is *not* text format. Whether a call is coming is ``forming``."""
        codec = JsonPromptStrategy.from_defaults()
        s = TextExtractionStrategy(codec)
        assert s.recognizes('{"tool": "greet"}')
        assert s.recognizes({"content": '{"tool": "greet"}'})
        assert s.recognizes("just some prose")                    # plain text is text format
        assert s.recognizes({"content": "just some prose"})
        assert not s.recognizes({"content": [{"type": "text"}]})  # Anthropic block list
        assert not s.recognizes({"tool_calls": []})               # OpenAI envelope

    def test_text_forming_detects_the_codec_marker(self):
        """forming = 'a call is coming': the codec's marker forms; plain prose does not."""
        codec = JsonPromptStrategy.from_defaults()
        s = TextExtractionStrategy(codec)
        assert s.forming('{"tool": "greet"}')
        assert s.forming({"content": '{"tool": "greet"}'})
        assert s.forming('{"tool": "greet"}').tool_name == "greet"
        assert not s.forming("just some prose")
        assert not s.forming({"content": "just some prose"})

    def test_recognizer_blocks_text_fallback_even_when_extract_returns_none(self):
        """The critical false-positive prevention test.

        A dict with ``tool_calls: None`` is recognised by OpenAI strategy.
        Even though extract returns None, text fallback must NOT run --
        the JSON in content must not be misinterpreted as a tool call.
        """
        driver = SimpleBaseDriver()
        response = {
            "role": "assistant",
            "content": '{"tool": "greet", "arguments": {}}',
            "tool_calls": None,
        }
        dr = driver.process_llm_response(response)
        assert not dr.call_executed
        assert not dr.call_failed

    def test_str_input_falls_through_to_text(self):
        """Pure str input: no strategy recognises → text fallback extracts."""
        driver = SimpleBaseDriver()
        dr = driver.process_llm_response('{"tool": "greet", "arguments": {}}')
        assert dr.call_executed is True

    def test_dict_without_tool_calls_key_uses_text_fallback(self):
        """Dict from text-model client (no tool_calls key) → text fallback."""
        driver = SimpleBaseDriver()
        dr = driver.process_llm_response(
            {"role": "assistant", "content": '{"tool": "greet", "arguments": {}}'}
        )
        assert dr.call_executed is True
