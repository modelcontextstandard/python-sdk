"""Native wire-format strategies: reassembly across Completions/Responses/Anthropic.

litellm normalises every provider onto the OpenAI *Completions* chunk shape, so the
Completions path is exercised live elsewhere. Responses and Anthropic are only seen
by clients on the *raw* SDKs -- here they are proven with synthetic fixtures built
from the exact event shapes in ``docs/Reference/streaming-tool-formats.md``.

The proof for each format: feed its raw events into an ``LLMStreamBuffer``; the buffer
must reassemble the provider's **native** ``stream=false`` message (Completions keeps
``tool_calls[]``, Responses an ``output[]`` item list, Anthropic a ``content[]`` block
list), and **that format's own** ``extract`` must yield ``(name, arguments)``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from mcs.driver.core import (
    BaseDriver,
    LLMStreamBuffer,
    ExtractedCall,
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


class FailingDriver(BaseDriver):
    """Owns ``send_mail`` but its execution always raises."""

    meta: DriverMeta = _Meta()

    def list_tools(self) -> list[Tool]:
        return [Tool("send_mail", description="Send a mail")]

    def execute_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        raise RuntimeError("smtp down")


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

    def test_tool_call_reassembled_to_native(self):
        buf = LLMStreamBuffer()
        buf.add(_resp_item_added("send_mail", "call_1"))
        buf.add(_resp_args_delta('{"to":'))
        buf.add(_resp_args_delta(' "a@b.c"}'))
        item = buf.as_dict()["output"][0]          # native Responses item, not tool_calls[]
        assert item["type"] == "function_call"
        assert item["call_id"] == "call_1"
        assert item["name"] == "send_mail"
        assert item["arguments"] == '{"to": "a@b.c"}'

    def test_native_extract_yields_name_and_args(self):
        buf = LLMStreamBuffer()
        buf.add(_resp_item_added("send_mail", "call_1"))
        buf.add(_resp_args_delta('{"to": "a@b.c"}'))
        assert OpenAIResponseExtractionStrategy().extract(buf.as_dict()) == [
            ExtractedCall("send_mail", {"to": "a@b.c"}, id="call_1")
        ]

    def test_executes_via_driver(self):
        driver = EchoDriver()
        buf = LLMStreamBuffer()
        buf.add(_resp_item_added("send_mail", "call_1"))
        buf.add(_resp_args_delta('{"to": "a@b.c"}'))
        buf.add({"type": "response.completed"})     # batch done
        dr = driver.process_llm_response(buf)
        assert dr.call_executed is True

    def test_is_finished_on_completed(self):
        buf = LLMStreamBuffer()
        buf.add(_resp_item_added("send_mail", "call_1"))
        assert buf.is_finished() is False
        buf.add({"type": "response.completed"})
        assert buf.is_finished() is True

    def test_text_delta_is_content(self):
        buf = LLMStreamBuffer()
        buf.add(_resp_text_delta("Hel"))
        buf.add(_resp_text_delta("lo"))
        assert buf.get_content() == "Hello"


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

    def test_tool_call_reassembled_to_native(self):
        buf = LLMStreamBuffer()
        buf.add({"type": "message_start"})
        buf.add(_anthropic_block_start("send_mail", "toolu_1", index=0))
        buf.add(_anthropic_json_delta('{"to":', index=0))
        buf.add(_anthropic_json_delta(' "a@b.c"}', index=0))
        block = buf.as_dict()["content"][0]        # native Anthropic block, not tool_calls[]
        assert block["type"] == "tool_use"
        assert block["id"] == "toolu_1"
        assert block["name"] == "send_mail"
        assert block["input_json"] == '{"to": "a@b.c"}'

    def test_native_extract_yields_name_and_args(self):
        buf = LLMStreamBuffer()
        buf.add(_anthropic_block_start("send_mail", "toolu_1"))
        buf.add(_anthropic_json_delta('{"to": "a@b.c"}'))
        assert AnthropicExtractionStrategy().extract(buf.as_dict()) == [
            ExtractedCall("send_mail", {"to": "a@b.c"}, id="toolu_1")
        ]

    def test_executes_via_driver(self):
        driver = EchoDriver()
        buf = LLMStreamBuffer()
        buf.add(_anthropic_block_start("send_mail", "toolu_1"))
        buf.add(_anthropic_json_delta('{"to": "a@b.c"}'))
        buf.add({"type": "message_stop"})           # batch done
        dr = driver.process_llm_response(buf)
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
        buf.add(_anthropic_text_delta("I'll check. "))
        assert buf.get_content() == "I'll check. "

    def test_text_then_tool_interleaved(self):
        """Claude streams a text preamble, then a tool_use block -- native block list."""
        buf = LLMStreamBuffer()
        buf.add({"type": "message_start"})
        buf.add(_anthropic_text_delta("Let me send that. ", index=0))
        buf.add(_anthropic_block_start("send_mail", "toolu_1", index=1))
        buf.add(_anthropic_json_delta("{}", index=1))
        msg = buf.as_dict()
        assert msg["content"][0] == {"type": "text", "text": "Let me send that. "}
        assert msg["content"][1]["type"] == "tool_use"
        assert msg["content"][1]["name"] == "send_mail"
        assert buf.get_content() == "Let me send that. "   # display text = the text block


def _oai_content_chunk(text: str) -> dict:
    return {"choices": [{"delta": {"content": text, "tool_calls": None}}]}


def _feed(driver, buf, frags):
    """Stream *frags* (content) chunk by chunk; return the response after the last.

    A text-embedded call is self-delimited, so it resolves on the content chunk that
    completes it -- no separate finish chunk needed (that is the native batch's gate)."""
    dr = None
    for frag in frags:
        buf.add(_oai_content_chunk(frag))
        dr = driver.process_llm_response(buf)
    return dr


class TestTextEmbeddedToolCall:
    """OpenAI models sometimes emit a tool call as JSON in `content`, not via native
    `tool_calls`. The buffer accumulates it as plain content (the wire is still
    OpenAI Completions); the driver's Text fallback (in its ExtractionChain)
    extracts it -- so it executes end to end. While it forms, the driver holds the
    buffer (`call_pending`, `buf.text()` empty) so the raw JSON does not leak into
    the display, then executes once the codec parses the complete call."""

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
        dr = _feed(driver, buf, (self._CALL[:10], self._CALL[10:28], self._CALL[28:]))
        assert dr.call_executed is True

    def test_partial_call_is_pending_and_held(self):
        """A forming text call for a known tool is held: call_pending, and buf.text()
        stays empty so the raw JSON never leaks into the display."""
        driver = EchoDriver()
        buf = LLMStreamBuffer()
        buf.add(_oai_content_chunk(self._CALL[:20]))     # {"tool": "send_mail" -- forming
        dr = driver.process_llm_response(buf)
        assert dr.call_pending is True
        assert dr.call_executed is False
        assert buf.text() == ""                           # held -- nothing leaks

    def test_foreign_tool_flows_as_text(self):
        """A text call naming a tool this driver does not own is released as text as
        soon as the name is clear -- a model *explaining* a call, not one to run. It
        is not held (short pending), not executed, not failed (SILENT default)."""
        driver = EchoDriver()                             # owns only send_mail
        buf = LLMStreamBuffer()
        buf.add(_oai_content_chunk('{"tool": "other_tool"'))
        dr = driver.process_llm_response(buf)
        assert dr.call_pending is False                   # name known + not mine -> released
        assert dr.call_executed is False
        assert dr.call_failed is False
        assert buf.text() == '{"tool": "other_tool"'      # flows as text

    def test_fenced_call_is_held(self):
        driver = EchoDriver()
        buf = LLMStreamBuffer()
        buf.add(_oai_content_chunk('```json\n{"tool": "send_mail"'))
        dr = driver.process_llm_response(buf)
        assert dr.call_pending is True
        assert buf.text() == ""

    def test_python_fence_is_not_held(self):
        """A ```python block is display content, not a call -- it must flow."""
        driver = EchoDriver()
        buf = LLMStreamBuffer()
        buf.add(_oai_content_chunk("```python\nprint("))
        dr = driver.process_llm_response(buf)
        assert dr.call_pending is False
        assert buf.text() == "```python\nprint("

    def test_forming_holds_then_executes_without_leaking(self):
        """Chunk by chunk: held+pending while forming, executes on the chunk that
        completes the call, and the raw JSON is never shown (reset discards it)."""
        driver = EchoDriver()
        buf = LLMStreamBuffer()
        frags = [self._CALL[i:i + 12] for i in range(0, len(self._CALL), 12)]
        shown, states = "", []
        for f in frags:
            buf.add(_oai_content_chunk(f))
            dr = driver.process_llm_response(buf)
            shown += buf.text()
            states.append((dr.call_pending, dr.call_executed))
        assert states[-1] == (False, True)                # last chunk completes -> executed
        assert all(pending for pending, _ in states[:-1])  # all earlier: held/pending
        assert shown == ""                                # nothing ever leaked

    def test_text_then_call_then_text(self):
        """One turn can stream text, then a tool call, then more text: both text spans
        are shown, the call is executed (its JSON never shown), the result is fed back.

        This is the interleaving the user saw live -- narration around a call in a
        single stream. Eager execution runs the call the moment it completes and
        ``reset``s, so the trailing text flows as fresh content afterwards."""
        driver = EchoDriver()                              # owns send_mail
        buf = LLMStreamBuffer()
        shown, executed, messages = "", False, None
        for c in ["I'll send it. ",                        # text BEFORE the call
                  '{"tool": "send_mail", ',                # call forms (held)
                  '"arguments": {"to": "a@b.c"}}',         # call completes -> execute
                  " All done."]:                           # text AFTER the call
            buf.add(_oai_content_chunk(c))
            dr = driver.process_llm_response(buf)
            shown += buf.text()
            if dr.call_executed:
                executed, messages = True, dr.messages
        assert executed is True
        assert "I'll send it." in shown and "All done." in shown   # both text spans shown
        assert "send_mail" not in shown and "{" not in shown       # the call JSON never leaked
        assert messages is not None                                # tool result fed back to the LLM

    def test_openai_style_name_arguments_leak_executes(self):
        """The exact OpenAI leak shape: {"name": ..., "arguments": ...} in content."""
        driver = EchoDriver()
        buf = LLMStreamBuffer()
        call = '{"name": "send_mail", "arguments": {"to": "a@b.c"}}'
        dr = _feed(driver, buf, (call[:12], call[12:30], call[30:]))
        assert dr.call_executed is True
        assert dr.executed_calls

    def test_leak_wrapped_in_prose_executes(self):
        """The call embedded in surrounding text (model narrates, then emits JSON)."""
        driver = EchoDriver()
        buf = LLMStreamBuffer()
        dr = _feed(driver, buf, ('Sure, sending now. ',
                                 '{"name": "send_mail", ',
                                 '"arguments": {"to": "a@b.c"}}'))
        assert dr.call_executed is True


def _oai_tool_chunk(call_id: str, name: str, args: str) -> dict:
    return {"choices": [{"delta": {"content": None, "tool_calls": [
        {"index": 0, "id": call_id, "type": "function",
         "function": {"name": name, "arguments": args}}]},
        "finish_reason": "tool_calls"}]}   # single complete chunk -> batch done


class TestNativeHistoryFormat:
    """A native tool call must be fed back in native shape (assistant.tool_calls +
    role='tool' result keyed by tool_call_id) so the model sees its call answered
    -- a `system` message with the raw result does not close a native call."""

    def test_native_call_uses_tool_role_and_call_id(self):
        driver = EchoDriver()
        buf = LLMStreamBuffer()
        buf.add(_oai_tool_chunk("call_9", "send_mail", '{"to": "a@b.c"}'))
        dr = driver.process_llm_response(buf)
        assert dr.call_executed is True
        assert dr.messages is not None
        assistant, result = dr.messages
        assert assistant["role"] == "assistant"
        assert assistant["tool_calls"][0]["id"] == "call_9"
        assert result["role"] == "tool"
        assert result["tool_call_id"] == "call_9"

    def test_text_embedded_call_keeps_simple_format(self):
        """A text-embedded call has no native id -> the simple assistant/system pair."""
        driver = EchoDriver()
        buf = LLMStreamBuffer()
        call = '{"name": "send_mail", "arguments": {"to": "a@b.c"}}'
        dr = _feed(driver, buf, (call[:20], call[20:]))
        assert dr.call_executed is True
        assert dr.messages is not None
        _, result = dr.messages
        assert result["role"] == "system"          # text path: no tool_call_id


def _oai_parallel_chunk() -> dict:
    """One chunk carrying two parallel tool calls + finish_reason (batch done)."""
    return {"choices": [{"delta": {"content": None, "tool_calls": [
        {"index": 0, "id": "call_1", "type": "function",
         "function": {"name": "send_mail", "arguments": '{"to": "a@b.c"}'}},
        {"index": 1, "id": "call_2", "type": "function",
         "function": {"name": "send_mail", "arguments": '{"to": "x@y.z"}'}},
    ]}, "finish_reason": "tool_calls"}]}


class TestParallelCalls:
    """OpenAI parallel calls: the whole batch executes at the DONE signal, and the
    native history carries all tool_calls + one role='tool' result per id."""

    def test_all_execute_with_native_history(self):
        driver = EchoDriver()
        buf = LLMStreamBuffer()
        buf.add(_oai_parallel_chunk())
        dr = driver.process_llm_response(buf)
        assert dr.call_executed is True

        assert dr.messages is not None
        assistant = dr.messages[0]
        assert assistant["role"] == "assistant"
        assert [tc["id"] for tc in assistant["tool_calls"]] == ["call_1", "call_2"]

        tool_results = dr.messages[1:]
        assert all(m["role"] == "tool" for m in tool_results)
        assert [m["tool_call_id"] for m in tool_results] == ["call_1", "call_2"]

    def test_pending_until_the_batch_is_done(self):
        """No early execute: a complete first call stays pending until finish."""
        driver = EchoDriver()
        buf = LLMStreamBuffer()
        # First call fully streamed, but the turn is not finished yet.
        buf.add(_oai_content_chunk(""))  # noop content to establish the OpenAI wire
        buf.add({"choices": [{"delta": {"tool_calls": [
            {"index": 0, "id": "call_1", "type": "function",
             "function": {"name": "send_mail", "arguments": '{"to": "a@b.c"}'}}]}}]})
        dr = driver.process_llm_response(buf)
        assert dr.call_pending is True
        assert dr.call_executed is False

    def test_executed_calls_report(self):
        """executed_calls carries a per-call record for the client."""
        driver = EchoDriver()
        buf = LLMStreamBuffer()
        buf.add(_oai_parallel_chunk())
        dr = driver.process_llm_response(buf)
        assert dr.executed_calls is not None
        assert [r.name for r in dr.executed_calls] == ["send_mail", "send_mail"]
        assert [r.tool_call_id for r in dr.executed_calls] == ["call_1", "call_2"]
        assert dr.executed_calls[0].arguments == {"to": "a@b.c"}
        assert dr.executed_calls[0].result is not None
        assert dr.executed_calls[0].error is None

    def test_foreign_tool_in_batch_is_ignored(self):
        """A tool this driver does not own is left untouched -- never errored.

        In a client's list of drivers another driver may own it (fan-out). Only the
        driver's own call runs, is reported, and is echoed + answered; the foreign
        call leaves no record and no dangling id in *this* driver's history."""
        driver = EchoDriver()
        buf = LLMStreamBuffer()
        buf.add({"choices": [{"delta": {"content": None, "tool_calls": [
            {"index": 0, "id": "call_1", "type": "function",
             "function": {"name": "send_mail", "arguments": "{}"}},
            {"index": 1, "id": "call_2", "type": "function",
             "function": {"name": "nonexistent", "arguments": "{}"}},
        ]}, "finish_reason": "tool_calls"}]})
        dr = driver.process_llm_response(buf)
        assert dr.call_executed is True
        assert dr.call_failed is False                        # nothing the driver ran failed
        assert [r.name for r in dr.executed_calls] == ["send_mail"]   # only its own
        # only the owned call is echoed and answered -- the foreign id is not ours
        assert [tc["id"] for tc in dr.messages[0]["tool_calls"]] == ["call_1"]
        assert [m["tool_call_id"] for m in dr.messages[1:]] == ["call_1"]

    def test_own_tool_error_still_answers_its_id(self):
        """When the driver's *own* tool raises, the batch fails but the call is still
        answered by id -- the error rides back as the tool result for self-heal."""
        driver = FailingDriver()
        buf = LLMStreamBuffer()
        buf.add(_oai_tool_chunk("call_9", "send_mail", "{}"))
        dr = driver.process_llm_response(buf)
        assert dr.call_failed is True
        assert dr.call_executed is False                      # nothing succeeded
        assert dr.executed_calls[0].error is not None
        assert dr.messages[1]["tool_call_id"] == "call_9"
        assert "smtp down" in dr.messages[1]["content"]


class TestNativeFanOut:
    """A chain of drivers over ONE buffer, native wire -- the counterpart to
    ``TestTextMultiCall.test_deferred_consume_is_fan_out_safe``.

    Fan-out means every driver sees the same buffer in the same round. A driver that
    finds a complete call it does not own still advances the buffer past it (otherwise
    the call would anchor the scan forever) -- but that drop must be **deferred** to the
    next chunk, or the first driver in the chain wipes the call before the driver that
    owns it ever looks. For a native batch there is no text offset, so the whole message
    is dropped; deferring it is what keeps a chain workable."""

    def test_unowned_native_call_survives_for_the_next_driver(self):
        """A does not own the call, B does: B must still see and run it this round."""
        a = MailAndLogDriver()                             # owns log_event, NOT send_mail
        b = EchoDriver()                                   # owns send_mail
        buf = LLMStreamBuffer()
        buf.add(_oai_tool_chunk("call_9", "send_mail", '{"to": "a@b.c"}'))

        dra = a.process_llm_response(buf)                  # A: not mine -> deferred drop
        assert dra.call_executed is False
        drb = b.process_llm_response(buf)                  # B: mine -> must still see it
        assert [r.name for r in (drb.executed_calls or [])] == ["send_mail"]
        assert drb.executed_calls[0].arguments == {"to": "a@b.c"}

    def test_call_owned_by_nobody_is_dropped_on_the_next_chunk(self):
        """The other half of the contract: once the whole chain has passed on a call,
        the next chunk drops it -- it must not be re-offered round after round."""
        a = MailAndLogDriver()
        b = EchoDriver()
        buf = LLMStreamBuffer()
        buf.add(_oai_tool_chunk("call_9", "nobodys_tool", "{}"))
        a.process_llm_response(buf)
        b.process_llm_response(buf)

        buf.add(_oai_content_chunk("Anyway, "))            # next round -> drop applies
        assert "tool_calls" not in buf.as_dict()
        assert a.process_llm_response(buf).call_executed is False
        assert b.process_llm_response(buf).call_executed is False


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


class MailAndLogDriver(BaseDriver):
    """Owns a *different* tool than EchoDriver -- for a two-driver fan-out chain."""

    meta: DriverMeta = _Meta()

    def list_tools(self) -> list[Tool]:
        return [Tool("log_event", description="Log an event")]

    def execute_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        return {"logged": arguments}


def _stream_text(driver, buf, text: str, size: int = 12):
    """Feed *text* as OpenAI content chunks of ~*size* chars (real streaming); return
    ``(shown, executed_records)`` -- what the driver let through + every executed call."""
    shown: str = ""
    records: list = []
    for i in range(0, len(text), size):
        buf.add(_oai_content_chunk(text[i:i + size]))
        dr = driver.process_llm_response(buf)
        shown += buf.text()
        if dr.executed_calls:
            records.extend(dr.executed_calls)
    return shown, records


class TestTextMultiCall:
    """Several text-embedded calls in one turn, streamed chunk by chunk. The driver
    advances past each handled call (``buf.consume_through``) keeping the tail, so a
    later call is never shadowed by an earlier one."""

    def test_two_unowned_calls_flow_and_nothing_runs(self):
        """The user's live case: two hypothetical (unowned) calls + prose. Both flow as
        text, neither executes, and the second is *not* anchored behind the first."""
        driver = EchoDriver()                              # owns send_mail only
        buf = LLMStreamBuffer()
        text = (
            "Hypothetisch:\n```json\n"
            '{"tool": "findCatsByTags", "arguments": {"tags": ["Mops"]}}\n```\n'
            "Oder:\n```json\n"
            '{"tool": "findCatsByTags", "arguments": {"tags": ["tag1", "tag2"]}}\n```\n'
            "Nur hypothetisch."
        )
        shown, records = _stream_text(driver, buf, text)
        assert records == []                               # nothing owned -> nothing ran
        assert "Hypothetisch" in shown and "Nur hypothetisch." in shown

    def test_unowned_example_then_owned_real_runs_the_real_one(self):
        """The dangerous case: an unowned example call first, the real owned call after.
        The real one is found and executed -- exactly what a first-only parse missed."""
        driver = EchoDriver()                              # owns send_mail
        buf = LLMStreamBuffer()
        text = (
            "Example:\n```json\n"
            '{"tool": "findCatsByTags", "arguments": {"tags": ["x"]}}\n```\n'
            "Now for real:\n```json\n"
            '{"tool": "send_mail", "arguments": {"to": "a@b.c"}}\n```'
        )
        _shown, records = _stream_text(driver, buf, text)
        assert [r.name for r in records] == ["send_mail"]
        assert records[0].arguments == {"to": "a@b.c"}

    def test_two_owned_calls_both_execute_in_order(self):
        """Two real owned calls in one turn: both run, in order -- the buffer advances
        past the first (keeping the tail) so the second streams in and executes too."""
        driver = EchoDriver()                              # owns send_mail
        buf = LLMStreamBuffer()
        text = (
            "First:\n```json\n{\"tool\": \"send_mail\", \"arguments\": {\"to\": \"a@b.c\"}}\n```\n"
            "Second:\n```json\n{\"tool\": \"send_mail\", \"arguments\": {\"to\": \"x@y.z\"}}\n```"
        )
        _shown, records = _stream_text(driver, buf, text)
        assert [r.arguments["to"] for r in records] == ["a@b.c", "x@y.z"]

    def test_deferred_consume_is_fan_out_safe(self):
        """A chain: driver A does not own the call, driver B does. A's advance is
        *deferred* (applied on the next add), so B still sees the call this round and
        executes it -- A never steals it."""
        a = MailAndLogDriver()                             # owns log_event, NOT send_mail
        b = EchoDriver()                                   # owns send_mail
        buf = LLMStreamBuffer()
        text = 'Do it:\n```json\n{"tool": "send_mail", "arguments": {"to": "a@b.c"}}\n```'
        executed: list = []
        for i in range(0, len(text), 12):
            buf.add(_oai_content_chunk(text[i:i + 12]))
            a.process_llm_response(buf)                    # A: not mine -> deferred consume
            drb = b.process_llm_response(buf)              # B: mine -> must still see + run it
            if drb.executed_calls:
                executed.extend(drb.executed_calls)
        assert [r.name for r in executed] == ["send_mail"]

    def test_whole_text_non_streaming_finds_both(self):
        """Non-streaming counterpart: the complete text yields both calls at once; only
        the owned one runs."""
        driver = EchoDriver()                              # owns send_mail
        text = (
            '```json\n{"tool": "findCatsByTags", "arguments": {}}\n```\n'
            '```json\n{"tool": "send_mail", "arguments": {"to": "a@b.c"}}\n```'
        )
        dr = driver.process_llm_response(text)
        assert dr.call_executed is True
        assert [r.name for r in dr.executed_calls] == ["send_mail"]

    def test_non_call_blocks_do_not_anchor_a_later_real_call(self):
        """The live native-leak case: the model narrates example blocks in an *unknown*
        format (``recipient_name``, not a call), then makes the real owned call. Each
        settled non-call block is advanced past (``settled_end``), so the scan does not
        stay anchored on the first block -- the real call is still found and executed."""
        driver = EchoDriver()                              # owns send_mail
        buf = LLMStreamBuffer()
        text = (
            "Beispiel Katzen:\n```json\n"
            '{"recipient_name": "functions.getCatsByTags", "parameters": {"tags": ["x"]}}\n```\n'
            "Beispiel Hunde:\n```json\n"
            '{"recipient_name": "functions.getDogsByTags", "parameters": {"tags": ["y"]}}\n```\n'
            "Echt:\n```json\n"
            '{"tool": "send_mail", "arguments": {"to": "a@b.c"}}\n```'
        )
        _shown, records = _stream_text(driver, buf, text)
        assert [r.name for r in records] == ["send_mail"]
        assert records[0].arguments == {"to": "a@b.c"}


class PetDriver(BaseDriver):
    """Owns ``findPetsByTags``; ``getCatsByTags`` / ``getDogsByTags`` are foreign."""

    meta: DriverMeta = _Meta()

    def list_tools(self) -> list[Tool]:
        return [Tool("findPetsByTags", description="Find pets by tags")]

    def execute_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        return {"found": arguments}


_OWNED = "findPetsByTags"


def _fenced_call(name: str, tag: str) -> str:
    """One MCS-format tool call as a fenced JSON block."""
    return f'```json\n{{"tool": "{name}", "arguments": {{"tags": ["{tag}"]}}}}\n```'


# owned (findPetsByTags) mixed with foreign (getCats/getDogs) at every position
_MIX_CASES = [
    ("all_owned",    [_OWNED, _OWNED]),
    ("all_foreign",  ["getCatsByTags", "getDogsByTags"]),
    ("owned_first",  [_OWNED, "getCatsByTags", "getDogsByTags"]),
    ("owned_last",   ["getCatsByTags", "getDogsByTags", _OWNED]),
    ("owned_middle", ["getCatsByTags", _OWNED, "getDogsByTags"]),
    ("interleaved",  ["getCatsByTags", _OWNED, "getDogsByTags", _OWNED]),
]


@pytest.mark.parametrize(
    "names", [c[1] for c in _MIX_CASES], ids=[c[0] for c in _MIX_CASES]
)
class TestMixedOwnership:
    """Owned and foreign text calls mixed at every position, at-once *and* streaming:
    only the owned calls run, in order; the foreign ones flow as text and never execute.
    Each foreign call is advanced past (settled_end) so it never shadows a later owned one."""

    def test_at_once(self, names):
        driver = PetDriver()
        text = "\n\n".join(_fenced_call(n, f"t{i}") for i, n in enumerate(names))
        dr = driver.process_llm_response(text)
        assert [r.name for r in (dr.executed_calls or [])] == [n for n in names if n == _OWNED]

    def test_streaming(self, names):
        driver = PetDriver()
        buf = LLMStreamBuffer()
        text = "\n\n".join(_fenced_call(n, f"t{i}") for i, n in enumerate(names))
        _shown, records = _stream_text(driver, buf, text)
        assert [r.name for r in records] == [n for n in names if n == _OWNED]


class TestToolUsesWrapperFormat:
    """The model's ``tool_uses`` / ``recipient_name`` / ``parameters`` format is NOT the
    MCS codec -> the whole wrapper is a single non-call object; it flows as text and
    nothing runs, even with a real tool name inside (MCS's stance: model-specific
    native-leak formats are the serving layer's job, not the client codec's)."""

    _WRAPPER = (
        "Parallel:\n```json\n"
        '{"tool_uses": ['
        '{"recipient_name": "functions.getCatsByTags", "parameters": {"tags": ["Mops"]}}, '
        '{"recipient_name": "functions.findPetsByTags", "parameters": {"tags": ["Mops"]}}'
        "]}\n```"
    )

    def test_at_once_runs_nothing(self):
        dr = PetDriver().process_llm_response(self._WRAPPER)
        assert dr.call_executed is False

    def test_streaming_flows_as_text(self):
        buf = LLMStreamBuffer()
        shown, records = _stream_text(PetDriver(), buf, self._WRAPPER)
        assert records == []
        assert "Parallel:" in shown


class TestForming:
    """forming() = 'a tool call is coming' (+ name once streamed), distinct from
    recognizes() = format identification."""

    def test_openai_forming_reports_name(self):
        s = OpenAICompletionExtractionStrategy()
        f = s.forming({"tool_calls": [{"function": {"name": "send_mail", "arguments": ""}}]})
        assert f and f.tool_name == "send_mail"          # forming even before args stream

    def test_openai_tool_calls_null_is_not_forming(self):
        """The false-positive shape: envelope present but no entry -> not forming."""
        s = OpenAICompletionExtractionStrategy()
        assert not s.forming({"content": "hi", "tool_calls": None})

    def test_anthropic_forming_on_tool_use_only(self):
        s = AnthropicExtractionStrategy()
        assert s.forming({"content": [{"type": "tool_use", "name": "send_mail"}]}).tool_name == "send_mail"
        assert not s.forming({"content": [{"type": "text", "text": "hi"}]})   # a leak is not forming here


class TestNativeLeakFallthrough:
    """An envelope format whose message always carries its structure (``leaks_into_text``)
    claims even a text-only message; when its ``extract`` finds no native call, the driver
    hands the plain text to the text backup -- catching a call the model *leaked* into a
    text block. Settable/clearable via set_native_backup_strategy."""

    _LEAK = '{"tool": "send_mail", "arguments": {"to": "a@b.c"}}'

    def test_anthropic_text_leak_executes_via_backup(self):
        driver = EchoDriver()                              # owns send_mail
        buf = LLMStreamBuffer()
        buf.add({"type": "message_start"})
        buf.add(_anthropic_text_delta(self._LEAK, index=0))  # call written as text, no tool_use
        dr = driver.process_llm_response(buf)              # eager: the leak is a complete call
        assert dr.call_executed is True
        _, result = dr.messages
        assert result["role"] == "system"                  # text path: no native tool_call_id

    def test_leak_uncaught_when_backup_disabled(self):
        driver = EchoDriver()
        driver.set_native_backup_strategy(None)            # disable the fall-through
        assert driver.get_native_backup_strategy() is None
        buf = LLMStreamBuffer()
        buf.add({"type": "message_start"})
        buf.add(_anthropic_text_delta(self._LEAK, index=0))
        buf.add({"type": "message_stop"})
        dr = driver.process_llm_response(buf)
        assert dr.call_executed is False                   # no backup -> leak flows as text

    def test_native_call_still_wins_over_backup(self):
        """A real tool_use block extracts natively -- the backup never runs, and the
        history is native Anthropic (user tool_result), not the text pair."""
        driver = EchoDriver()
        buf = LLMStreamBuffer()
        buf.add(_anthropic_block_start("send_mail", "toolu_1"))
        buf.add(_anthropic_json_delta("{}"))
        buf.add({"type": "message_stop"})
        dr = driver.process_llm_response(buf)
        assert dr.call_executed is True
        _, result = dr.messages
        assert result["role"] == "user"                    # native Anthropic tool_result
