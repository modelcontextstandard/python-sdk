"""Native wire-format strategies: reassembly across Completions/Responses/Anthropic.

litellm normalises every provider onto the OpenAI *Completions* chunk shape, so the
Completions path is exercised live elsewhere. Responses and Anthropic are only seen
by clients on the *raw* SDKs -- here they are proven with synthetic fixtures built
from the exact event shapes in ``docs/streaming-tool-formats.md``.

The proof for each format: feed its raw events into an ``LLMStreamBuffer``; the
buffer must produce the **canonical** message (``tool_calls[]``), and the shared
canonical ``extract`` must yield ``(name, arguments)``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from mcs.driver.core import (
    BaseDriver,
    LLMStreamBuffer,
    OpenAICompletionExtractionStrategy,
    OpenAIResponseExtractionStrategy,
    AnthropicExtractionStrategy,
    DriverMeta,
    DriverBinding,
    Tool,
)


# -- A minimal concrete driver ----------------------------------------------

@dataclass(frozen=True)
class _Meta(DriverMeta):
    id: str = "native-0001"
    name: str = "Native Test Driver"
    version: str = "0.0.1"
    bindings: tuple[DriverBinding, ...] = ()
    supported_llms: tuple[str, ...] | None = None
    capabilities: tuple[str, ...] = ()


class EchoDriver(BaseDriver):
    meta: DriverMeta = _Meta()

    def list_tools(self) -> list[Tool]:
        return [Tool("send_mail", description="Send a mail")]

    def execute_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        return {"sent": tool_name, "args": arguments}


_CANONICAL = OpenAICompletionExtractionStrategy()  # the shared extractor


# -- OpenAI Responses fixtures ------------------------------------------------

def _resp_item_added(name: str, call_id: str, output_index: int = 0) -> dict:
    return {
        "type": "response.output_item.added",
        "output_index": output_index,
        "item": {"type": "function_call", "id": "fc_1", "call_id": call_id, "name": name},
    }


def _resp_args_delta(delta: str, output_index: int = 0) -> dict:
    return {
        "type": "response.function_call_arguments.delta",
        "output_index": output_index,
        "delta": delta,
    }


def _resp_text_delta(text: str) -> dict:
    return {"type": "response.output_text.delta", "delta": text}


class TestOpenAIResponses:

    def test_wire_is_recognised(self):
        buf = LLMStreamBuffer()
        buf.add(_resp_item_added("send_mail", "call_1"))
        assert isinstance(buf._active, OpenAIResponseExtractionStrategy)

    def test_tool_call_reassembled_to_canonical(self):
        buf = LLMStreamBuffer()
        buf.add(_resp_item_added("send_mail", "call_1"))
        buf.add(_resp_args_delta('{"to":'))
        buf.add(_resp_args_delta(' "a@b.c"}'))
        tc = buf.as_dict()["tool_calls"][0]
        assert tc["id"] == "call_1"
        assert tc["function"]["name"] == "send_mail"
        assert tc["function"]["arguments"] == '{"to": "a@b.c"}'

    def test_canonical_extract_yields_name_and_args(self):
        buf = LLMStreamBuffer()
        buf.add(_resp_item_added("send_mail", "call_1"))
        buf.add(_resp_args_delta('{"to": "a@b.c"}'))
        assert _CANONICAL.extract(buf.as_dict()) == ("send_mail", {"to": "a@b.c"})

    def test_executes_via_driver(self):
        driver = EchoDriver()
        buf = LLMStreamBuffer()
        buf.add(_resp_item_added("send_mail", "call_1"))
        buf.add(_resp_args_delta('{"to": "a@b.c"}'))
        dr = driver.process_llm_response(buf.as_dict(), streaming=True)
        assert dr.call_executed is True

    def test_is_finished_on_completed(self):
        buf = LLMStreamBuffer()
        buf.add(_resp_item_added("send_mail", "call_1"))
        assert buf.is_finished() is False
        buf.add({"type": "response.completed"})
        assert buf.is_finished() is True

    def test_text_delta_is_content(self):
        buf = LLMStreamBuffer()
        assert buf.add(_resp_text_delta("Hel")) == "Hel"
        buf.add(_resp_text_delta("lo"))
        assert buf.as_dict()["content"] == "Hello"


# -- Anthropic fixtures -------------------------------------------------------

def _anthropic_block_start(name: str, block_id: str, index: int = 0) -> dict:
    return {
        "type": "content_block_start",
        "index": index,
        "content_block": {"type": "tool_use", "id": block_id, "name": name, "input": {}},
    }


def _anthropic_json_delta(partial: str, index: int = 0) -> dict:
    return {
        "type": "content_block_delta",
        "index": index,
        "delta": {"type": "input_json_delta", "partial_json": partial},
    }


def _anthropic_text_delta(text: str, index: int = 0) -> dict:
    return {
        "type": "content_block_delta",
        "index": index,
        "delta": {"type": "text_delta", "text": text},
    }


class TestAnthropic:

    def test_wire_is_recognised(self):
        buf = LLMStreamBuffer()
        buf.add({"type": "message_start"})
        assert isinstance(buf._active, AnthropicExtractionStrategy)

    def test_tool_call_reassembled_to_canonical(self):
        buf = LLMStreamBuffer()
        buf.add({"type": "message_start"})
        buf.add(_anthropic_block_start("send_mail", "toolu_1", index=0))
        buf.add(_anthropic_json_delta('{"to":', index=0))
        buf.add(_anthropic_json_delta(' "a@b.c"}', index=0))
        tc = buf.as_dict()["tool_calls"][0]
        assert tc["id"] == "toolu_1"
        assert tc["function"]["name"] == "send_mail"
        assert tc["function"]["arguments"] == '{"to": "a@b.c"}'

    def test_canonical_extract_yields_name_and_args(self):
        buf = LLMStreamBuffer()
        buf.add(_anthropic_block_start("send_mail", "toolu_1"))
        buf.add(_anthropic_json_delta('{"to": "a@b.c"}'))
        assert _CANONICAL.extract(buf.as_dict()) == ("send_mail", {"to": "a@b.c"})

    def test_executes_via_driver(self):
        driver = EchoDriver()
        buf = LLMStreamBuffer()
        buf.add(_anthropic_block_start("send_mail", "toolu_1"))
        buf.add(_anthropic_json_delta('{"to": "a@b.c"}'))
        dr = driver.process_llm_response(buf.as_dict(), streaming=True)
        assert dr.call_executed is True

    def test_is_finished_on_message_stop(self):
        buf = LLMStreamBuffer()
        buf.add(_anthropic_block_start("send_mail", "toolu_1"))
        assert buf.is_finished() is False
        buf.add({"type": "message_stop"})
        assert buf.is_finished() is True

    def test_text_delta_is_content(self):
        buf = LLMStreamBuffer()
        buf.add({"type": "message_start"})
        assert buf.add(_anthropic_text_delta("I'll check. ")) == "I'll check. "
        assert buf.as_dict()["content"] == "I'll check. "

    def test_text_then_tool_interleaved(self):
        """Claude streams a text preamble, then a tool_use block."""
        buf = LLMStreamBuffer()
        buf.add({"type": "message_start"})
        buf.add(_anthropic_text_delta("Let me send that. ", index=0))
        buf.add(_anthropic_block_start("send_mail", "toolu_1", index=1))
        buf.add(_anthropic_json_delta("{}", index=1))
        msg = buf.as_dict()
        assert msg["content"] == "Let me send that. "
        assert msg["tool_calls"][1]["function"]["name"] == "send_mail"


def _oai_content_chunk(text: str) -> dict:
    return {"choices": [{"delta": {"content": text, "tool_calls": None}}]}


class TestTextEmbeddedToolCall:
    """OpenAI models sometimes emit a tool call as JSON in `content`, not via native
    `tool_calls`. The buffer accumulates it as plain content (the wire is still
    OpenAI Completions); the driver's Text fallback (in its ExtractionChain)
    extracts it -- so it executes end to end. Known gap: mid-stream there is no
    `call_pending` for text mode; the partial JSON reads as plain content until it
    parses."""

    _CALL = '{"tool": "send_mail", "arguments": {"to": "a@b.c"}}'

    def test_accumulates_as_content_never_a_native_call(self):
        buf = LLMStreamBuffer()
        for frag in (self._CALL[:10], self._CALL[10:28], self._CALL[28:]):
            buf.add(_oai_content_chunk(frag))
        msg = buf.as_dict()
        assert msg["content"] == self._CALL
        assert "tool_calls" not in msg

    def test_driver_text_fallback_executes_it(self):
        driver = EchoDriver()
        buf = LLMStreamBuffer()
        for frag in (self._CALL[:10], self._CALL[10:28], self._CALL[28:]):
            buf.add(_oai_content_chunk(frag))
        dr = driver.process_llm_response(buf.as_dict(), streaming=True)
        assert dr.call_executed is True

    def test_partial_reads_as_plain_text_not_pending(self):
        """The current limitation: a forming text call is not `call_pending`."""
        driver = EchoDriver()
        buf = LLMStreamBuffer()
        buf.add(_oai_content_chunk(self._CALL[:20]))     # incomplete JSON in content
        dr = driver.process_llm_response(buf.as_dict(), streaming=True)
        assert dr.call_pending is False
        assert dr.call_executed is False

    def test_openai_style_name_arguments_leak_executes(self):
        """The exact OpenAI leak shape: {"name": ..., "arguments": ...} in content."""
        driver = EchoDriver()
        buf = LLMStreamBuffer()
        call = '{"name": "send_mail", "arguments": {"to": "a@b.c"}}'
        for frag in (call[:12], call[12:30], call[30:]):
            buf.add(_oai_content_chunk(frag))
        assert "tool_calls" not in buf.as_dict()
        dr = driver.process_llm_response(buf.as_dict(), streaming=True)
        assert dr.call_executed is True
        assert dr.tool_call_result is not None

    def test_leak_wrapped_in_prose_executes(self):
        """The call embedded in surrounding text (model narrates, then emits JSON)."""
        driver = EchoDriver()
        buf = LLMStreamBuffer()
        for frag in ('Sure, sending now. ',
                     '{"name": "send_mail", ',
                     '"arguments": {"to": "a@b.c"}}'):
            buf.add(_oai_content_chunk(frag))
        dr = driver.process_llm_response(buf.as_dict(), streaming=True)
        assert dr.call_executed is True


class TestFormatIsolation:
    """Each format's events are recognised only by its own strategy."""

    def test_completion_not_claimed_by_others(self):
        chunk = {"choices": [{"delta": {"tool_calls": [{"index": 0, "id": "c1",
                 "function": {"name": "send_mail", "arguments": "{}"}}]}}]}
        assert OpenAICompletionExtractionStrategy().recognizes(chunk)
        assert not OpenAIResponseExtractionStrategy().recognizes(chunk)
        assert not AnthropicExtractionStrategy().recognizes(chunk)

    def test_responses_not_claimed_by_others(self):
        ev = _resp_item_added("send_mail", "call_1")
        assert OpenAIResponseExtractionStrategy().recognizes(ev)
        assert not AnthropicExtractionStrategy().recognizes(ev)
        assert not OpenAICompletionExtractionStrategy().recognizes(ev)

    def test_anthropic_not_claimed_by_others(self):
        ev = _anthropic_block_start("send_mail", "toolu_1")
        assert AnthropicExtractionStrategy().recognizes(ev)
        assert not OpenAIResponseExtractionStrategy().recognizes(ev)
        assert not OpenAICompletionExtractionStrategy().recognizes(ev)
