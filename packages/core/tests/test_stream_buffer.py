"""Tests for LLMStreamBuffer accumulation and streaming process_llm_response.

The streaming path: the client feeds raw provider chunks into a LLMStreamBuffer
(``buf.add(chunk)``) and hands ``buf.as_dict()`` to
``process_llm_response(..., streaming=True)``. The buffer reassembles content +
native tool_calls; the driver reports ``call_pending`` while the call is still
incomplete and ``call_executed`` once it is whole.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any

from mcs.driver.core import (
    BaseDriver,
    LLMStreamBuffer,
    DriverMeta,
    DriverBinding,
    Tool,
)


# -- A minimal concrete driver ----------------------------------------------

@dataclass(frozen=True)
class _Meta(DriverMeta):
    id: str = "stream-0001"
    name: str = "Stream Test Driver"
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


# -- Chunk helpers (simulate litellm streaming chunks) -----------------------

def _content_chunk(text: str) -> SimpleNamespace:
    delta = SimpleNamespace(content=text, tool_calls=None)
    return SimpleNamespace(choices=[SimpleNamespace(delta=delta)])


def _tool_chunk(index: int = 0, id: str | None = None,
                name: str | None = None, args: str | None = None) -> SimpleNamespace:
    fn = SimpleNamespace(name=name, arguments=args)
    tc = SimpleNamespace(index=index, id=id, function=fn)
    delta = SimpleNamespace(content=None, tool_calls=[tc])
    return SimpleNamespace(choices=[SimpleNamespace(delta=delta)])


class TestLLMStreamBufferAccumulation:

    def test_content_deltas_concatenated(self):
        buf = LLMStreamBuffer()
        buf.add(_content_chunk("Hel"))
        buf.add(_content_chunk("lo"))
        assert buf.as_dict() == {"role": "assistant", "content": "Hello"}

    def test_tool_call_reassembled_by_fragments(self):
        buf = LLMStreamBuffer()
        buf.add(_tool_chunk(0, id="call_1", name="send_mail"))
        buf.add(_tool_chunk(0, args='{"to":'))
        buf.add(_tool_chunk(0, args='"a@b.c"}'))
        tc = buf.as_dict()["tool_calls"][0]
        assert tc["id"] == "call_1"
        assert tc["function"]["name"] == "send_mail"
        assert tc["function"]["arguments"] == '{"to":"a@b.c"}'

    def test_content_and_tool_call_together(self):
        buf = LLMStreamBuffer()
        buf.add(_content_chunk("Let me send that. "))
        buf.add(_tool_chunk(0, id="c1", name="send_mail", args="{}"))
        msg = buf.as_dict()
        assert msg["content"] == "Let me send that. "
        assert msg["tool_calls"][0]["function"]["name"] == "send_mail"

    def test_accepts_dict_chunks(self):
        buf = LLMStreamBuffer()
        buf.add({"choices": [{"delta": {"content": "hi", "tool_calls": None}}]})
        assert buf.as_dict()["content"] == "hi"

    def test_empty_stream_yields_none_content(self):
        assert LLMStreamBuffer().as_dict() == {"role": "assistant", "content": None}


class TestStreamingProcessLlmResponse:

    def test_incomplete_tool_call_is_pending(self):
        """Name present, arguments still partial JSON -> call_pending, not fail."""
        driver = EchoDriver()
        buf = LLMStreamBuffer()
        buf.add(_tool_chunk(0, id="c1", name="send_mail"))
        buf.add(_tool_chunk(0, args='{"to":'))          # partial, unparseable
        dr = driver.process_llm_response(buf.as_dict(), streaming=True)
        assert dr.call_pending is True
        assert dr.call_executed is False
        assert dr.call_failed is False

    def test_name_only_is_pending(self):
        """A first chunk carrying only the name (args still "") is incomplete.

        Empty arguments mean "not streamed yet", not "no-arg call" -- so the
        driver reports call_pending and the client keeps buffering. This is what
        makes per-chunk processing safe: the name-only delta never executes.
        """
        driver = EchoDriver()
        buf = LLMStreamBuffer()
        buf.add(_tool_chunk(0, id="c1", name="send_mail"))   # args stays ""
        dr = driver.process_llm_response(buf.as_dict(), streaming=True)
        assert dr.call_pending is True
        assert dr.call_executed is False

    def test_complete_tool_call_executes(self):
        driver = EchoDriver()
        buf = LLMStreamBuffer()
        buf.add(_tool_chunk(0, id="c1", name="send_mail"))
        buf.add(_tool_chunk(0, args='{"to": "a@b.c"}'))
        dr = driver.process_llm_response(buf.as_dict(), streaming=True)
        assert dr.call_executed is True
        assert dr.call_pending is False
        assert dr.tool_call_result is not None

    def test_no_arg_call_executes(self):
        """A genuine no-argument call sends "{}" and executes (empty "" is pending)."""
        driver = EchoDriver()
        buf = LLMStreamBuffer()
        buf.add(_tool_chunk(0, id="c1", name="send_mail", args="{}"))
        dr = driver.process_llm_response(buf.as_dict(), streaming=True)
        assert dr.call_executed is True

    def test_plain_text_is_not_pending(self):
        """Content with no tool_calls key -> no call, no pending (final answer)."""
        driver = EchoDriver()
        buf = LLMStreamBuffer()
        buf.add(_content_chunk("Just a normal answer."))
        dr = driver.process_llm_response(buf.as_dict(), streaming=True)
        assert dr.call_pending is False
        assert dr.call_executed is False
        assert dr.call_failed is False

    def test_non_streaming_incomplete_is_no_call(self):
        """Without streaming, an incomplete call is treated as 'no call' (no pending)."""
        driver = EchoDriver()
        buf = LLMStreamBuffer()
        buf.add(_tool_chunk(0, id="c1", name="send_mail"))
        buf.add(_tool_chunk(0, args='{"to":'))
        dr = driver.process_llm_response(buf.as_dict(), streaming=False)
        assert dr.call_pending is False
        assert dr.call_executed is False

    def test_full_streaming_loop(self):
        """End-to-end: feed chunks one by one, pending until the last fragment."""
        driver = EchoDriver()
        buf = LLMStreamBuffer()
        fragments = [
            _tool_chunk(0, id="c1", name="send_mail"),        # name only, args="" -> pending
            _tool_chunk(0, args='{"to"'),                      # partial JSON     -> pending
            _tool_chunk(0, args=': "a@b.c"}'),                 # complete          -> execute
        ]
        states = []
        for chunk in fragments:
            buf.add(chunk)
            dr = driver.process_llm_response(buf.as_dict(), streaming=True)
            states.append((dr.call_pending, dr.call_executed))
        assert states == [(True, False), (True, False), (False, True)]
