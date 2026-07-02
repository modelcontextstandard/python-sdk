"""LLMStreamBuffer -- reassemble an LLM's streaming chunks into a full message.

A streaming client receives the LLM response chunk-by-chunk. Reassembling it --
concatenating ``content``, stitching native tool-call fragments together -- is
boilerplate every client would otherwise repeat. ``LLMStreamBuffer`` holds that
state so the client does not:

    buf = LLMStreamBuffer()
    for chunk in stream:
        text = buf.add(chunk)                          # feed raw chunk; get content delta
        dr = streamer.process_llm_response(buf.as_dict(), streaming=True)
        if dr.call_executed or dr.call_failed:
            buf.reset()                                # done with this call; find the next
        elif dr.call_pending:
            ...                                        # a tool call is building up
        elif text:
            print(text, end="")                        # content token

The buffer is **MCS** -- and MCS is SDK-, provider- and LLM-agnostic. It does not
know litellm or any SDK; it knows **tool formats**. Per-format reassembly lives on
the :class:`~mcs.driver.core.ExtractionStrategy` subclasses (their ``accumulate`` /
``is_done``); the buffer only holds the accumulator and **delegates** to the format
it recognises from the stream. It is *not* bound to any driver -- the same
reassembly applies no matter which driver eventually executes the call (a core MCS
promise: drivers compose). It therefore ships the MCS-default native wire formats
and is created directly by the client.

See ``packages/core/docs/streaming-tool-formats.md`` for the format matrix.
"""

from __future__ import annotations

from typing import Any

from .extraction_strategy import (
    ExtractionStrategy,
    OpenAICompletionExtractionStrategy,
    OpenAIResponseExtractionStrategy,
    AnthropicExtractionStrategy,
)


def _default_strategies() -> list[ExtractionStrategy]:
    """The MCS-default native wire formats, most common first.

    OpenAI Chat Completions is the baseline (what litellm normalises every
    provider to); Responses and Anthropic recognise their own event streams.
    """
    return [
        OpenAICompletionExtractionStrategy(),
        OpenAIResponseExtractionStrategy(),
        AnthropicExtractionStrategy(),
    ]


class LLMStreamBuffer:
    """Accumulate streaming chunks into the message dict ``process_llm_response`` expects.

    Holds the accumulator; delegates the format-specific stitching to the
    :class:`ExtractionStrategy` it recognises from the first chunk (constant for a
    stream). ``as_dict()`` yields the canonical message so far; ``is_finished()``
    reports the format's stream-done signal; ``reset()`` clears the accumulator to
    hunt for the next call in the same stream.
    """

    def __init__(
        self,
        strategies: list[ExtractionStrategy] | None = None,
        model_name: str | None = None,
    ) -> None:
        self._strategies = strategies or _default_strategies()
        self._model_name = model_name
        self._active: ExtractionStrategy | None = None
        self._acc: dict[str, Any] = self._fresh_acc()
        self._finished = False

    @staticmethod
    def _fresh_acc() -> dict[str, Any]:
        return {"role": "assistant", "content": None, "tool_calls": []}

    def add(self, chunk: Any) -> str | None:
        """Feed one raw provider chunk; accumulate internally.

        Resolves the wire format on the first chunk (it does not change within a
        stream) and delegates reassembly to it. Returns the **content delta** of
        this chunk for live display, or ``None`` (e.g. a tool-call fragment).
        """
        if self._active is None:
            self._active = self._resolve(chunk)
        text = self._active.accumulate(self._acc, chunk)
        if self._active.is_done(chunk):
            self._finished = True
        return text

    def as_dict(self) -> dict[str, Any]:
        """Return the message accumulated so far, ready for ``process_llm_response``."""
        msg: dict[str, Any] = {"role": "assistant", "content": self._acc["content"] or None}
        if self._acc["tool_calls"]:
            msg["tool_calls"] = self._acc["tool_calls"]
        return msg

    def is_finished(self) -> bool:
        """``True`` once the active format signalled the stream's completion."""
        return self._finished

    def has_tool_call(self) -> bool:
        """``True`` once any tool-call fragment has been accumulated."""
        return bool(self._acc["tool_calls"])

    def reset(self) -> None:
        """Clear the accumulator to hunt for the next call; keep the wire format.

        The stream's format does not change, so ``_active`` is retained -- only the
        accumulated content / tool calls and the done flag are cleared.
        """
        self._acc = self._fresh_acc()
        self._finished = False

    # -- internals ------------------------------------------------------------

    def _resolve(self, chunk: Any) -> ExtractionStrategy:
        """Pick the format that recognises *chunk*, defaulting to the baseline wire."""
        for strategy in self._strategies:
            if strategy.recognizes(chunk):
                return strategy
        return self._strategies[0]
