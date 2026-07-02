"""LLMStreamBuffer -- reassemble an LLM's streaming chunks into a full message.

A streaming client receives the LLM response chunk-by-chunk. Reassembling it --
concatenating ``content``, stitching native tool-call fragments together -- is
boilerplate every client would otherwise repeat. ``LLMStreamBuffer`` holds that
state so the client does not, and then **hands itself to the driver**:

    buf = LLMStreamBuffer()
    for chunk in stream:
        buf.add(chunk)                                 # feed raw chunk
        dr = streamer.process_llm_response(buf)        # the buffer IS the streaming signal
        if (text := buf.text()):
            print(text, end="")                        # what the driver let through
        # on call_executed the driver ran the tool and cleared the buffer itself

The client never picks ``content`` and ``tool_calls`` apart, and never decides
what to print -- the driver classifies streamed content as *releasable text* vs.
*a tool call in flight* (which it holds via :meth:`~LLMStreamBuffer.hold`). Display
stays with the buffer (:meth:`~LLMStreamBuffer.text`); the driver only reports status.

The buffer is **MCS** -- and MCS is SDK-, provider- and LLM-agnostic. It does not
know litellm or any SDK; it knows **tool formats**. Per-format reassembly lives on
the :class:`~mcs.driver.core.ExtractionStrategy` subclasses (their ``accumulate``);
the buffer only holds the accumulator, delegates to the format it recognises, and
tracks a **display cursor** so the driver can hold/release content. It is *not*
bound to any driver -- the same reassembly applies no matter which driver executes
the call. It ships the MCS-default native wire formats and is created by the client.

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
    """The MCS-default native wire formats, most common first."""
    return [
        OpenAICompletionExtractionStrategy(),
        OpenAIResponseExtractionStrategy(),
        AnthropicExtractionStrategy(),
    ]


class LLMStreamBuffer:
    """Accumulate streaming chunks; expose a typed API + a display cursor.

    The driver reads the buffer via :meth:`get_content` / :meth:`get_tool_calls`
    (not a stringly-keyed dict) and, for a forming call, holds display via
    :meth:`hold`; the client reads :meth:`text` for what may be shown. ``as_dict()``
    is internal
    -- it bridges the buffer to the ``str | dict``-based ``ExtractionStrategy``
    chain, which also serves the non-streaming path.
    """

    def __init__(
        self,
        strategies: list[ExtractionStrategy] | None = None,
        model_name: str | None = None,
    ) -> None:
        self._strategies = strategies or _default_strategies()
        self._model_name = model_name
        self._active: ExtractionStrategy | None = None
        self._content: str = ""
        self._tool_calls: list[dict[str, Any]] = []
        self._finished = False
        self._shown = 0                 # display cursor: chars already shown
        self._held = False              # this round's display veto (reset by add)

    def add(self, chunk: Any) -> None:
        """Feed one raw provider chunk; accumulate internally.

        Resolves the wire format on the first chunk (it does not change within a
        stream) and delegates reassembly to it. Returns nothing -- what may be
        *shown* is decided by the driver (via :meth:`hold`) and read via
        :meth:`text`, not here. Resets the per-round display veto (default: flow).
        """
        self._held = False
        if self._active is None:
            self._active = self._resolve(chunk)
        acc = {"content": self._content, "tool_calls": self._tool_calls}
        self._active.accumulate(acc, chunk)
        self._content = acc["content"] or ""
        self._tool_calls = acc["tool_calls"]
        if self._active.is_done(chunk):
            self._finished = True

    # -- typed read API -------------------------------------------------------

    def get_content(self) -> str | None:
        """The full accumulated content so far (``None`` if empty)."""
        return self._content or None

    def get_tool_calls(self) -> list[dict[str, Any]]:
        """The accumulated native tool calls (canonical OpenAI-message shape)."""
        return self._tool_calls

    def has_tool_call(self) -> bool:
        """``True`` once any tool-call fragment has been accumulated."""
        return bool(self._tool_calls)

    def is_finished(self) -> bool:
        """``True`` once the active format signalled the stream's completion."""
        return self._finished

    # -- display (driver holds; client reads) ---------------------------------

    def hold(self) -> None:
        """Suppress display for this round -- a tool call may be forming.

        A veto called by the driver inside ``process_llm_response``. If *any*
        driver in a chain holds, :meth:`text` yields nothing this round; the held
        content is released later, once no driver holds it (e.g. the name turns
        out not to be a tool). The veto resets each round (see :meth:`add`), so
        the default is to flow.
        """
        self._held = True

    def text(self) -> str:
        """The content the client may show now -- empty while held.

        Read *after* ``process_llm_response(buf)``: the driver has had its say. If
        nothing held it, returns the content since it was last shown; if a driver
        held it, returns ``""`` (and signals via its ``DriverResponse``).
        """
        if self._held:
            return ""
        out = self._content[self._shown:]
        self._shown = len(self._content)
        return out

    # -- lifecycle ------------------------------------------------------------

    def reset(self) -> None:
        """Clear the accumulator to hunt for the next call; keep the wire format.

        Called by the **driver** once it has consumed a call (executed/failed) --
        buffer lifecycle is the driver's concern, not the client's.
        """
        self._content = ""
        self._tool_calls = []
        self._finished = False
        self._shown = 0
        self._held = False

    def as_dict(self) -> dict[str, Any]:
        """Internal: the message so far, for the ``ExtractionStrategy`` chain."""
        msg: dict[str, Any] = {"role": "assistant", "content": self._content or None}
        if self._tool_calls:
            msg["tool_calls"] = self._tool_calls
        return msg

    # -- internals ------------------------------------------------------------

    def _resolve(self, chunk: Any) -> ExtractionStrategy:
        """Pick the format that recognises *chunk*, defaulting to the baseline wire."""
        for strategy in self._strategies:
            if strategy.recognizes(chunk):
                return strategy
        return self._strategies[0]
