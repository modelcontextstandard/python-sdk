"""LLMStreamBuffer -- reassemble an LLM's streaming chunks into a full message.

A streaming client receives the LLM response chunk-by-chunk. Reassembling it --
concatenating text, stitching native tool-call fragments together -- is boilerplate
every client would otherwise repeat. ``LLMStreamBuffer`` holds that state so the client
does not, and then **hands itself to the driver**:

    buf = streamer.new_stream_buffer()             # or LLMStreamBuffer(strategies)
    for chunk in stream:
        buf.add(chunk)                             # feed raw chunk
        dr = streamer.process_llm_response(buf)    # the buffer IS the streaming signal
        if (text := buf.text()):
            print(text, end="")                    # what the driver let through
        # on call_executed the driver ran the tool and cleared the buffer itself

The client never picks the message apart, and never decides what to print -- the driver
classifies streamed content as *releasable text* vs. *a tool call in flight* (which it
holds via :meth:`hold`). Display stays with the buffer (:meth:`text`); the driver only
reports status.

The buffer **reassembles into the format's native shape** -- the exact message the
provider's SDK returns for ``stream=false``. It does **not** normalise: an Anthropic
stream reassembles into an Anthropic message (a ``content`` block list), OpenAI into
``{content, tool_calls}``, Responses into an ``output`` item list. Per-format reassembly
lives on the :class:`~mcs.driver.core.ExtractionStrategy` subclasses (their
``accumulate``); the buffer only resolves the *wire* format once, holds the native
accumulator, and tracks a **display cursor** over the content deltas each ``accumulate``
returns -- so display text stays format-agnostic even when ``content`` is a block list.

The buffer is **MCS** -- SDK-, provider- and LLM-agnostic, and *not* bound to any driver:
the same reassembly applies no matter which driver executes the call, which is what lets
a client feed one buffer through a *list* of drivers (fan-out). It ships the MCS-default
native wire formats; ``SupportsStreaming.new_stream_buffer`` pre-seeds it with the
driver's chain as a convenience.

See ``docs/adr/0001-streaming-extraction-native-reassembly.md`` and
``docs/Reference/streaming-tool-formats.md`` for the format matrix.
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

    These are the *wire* (reassembly) strategies the buffer resolves over. The text
    strategy is not among them -- it does not reassemble a wire, so it never claims a
    raw chunk; it is a driver-side *extraction* strategy only.
    """
    return [
        OpenAICompletionExtractionStrategy(),
        OpenAIResponseExtractionStrategy(),
        AnthropicExtractionStrategy(),
    ]


class LLMStreamBuffer:
    """Accumulate streaming chunks into the native message; expose a display cursor.

    The driver reads the assembled message via :meth:`as_dict` (native shape) and, for a
    forming call, holds display via :meth:`hold`; the client reads :meth:`text` for what
    may be shown. The buffer resolves the *wire* format on the first chunk (it does not
    change within a stream) and delegates reassembly to it.
    """

    def __init__(
        self,
        strategies: list[ExtractionStrategy] | None = None,
        model_name: str | None = None,
    ) -> None:
        self._strategies = strategies or _default_strategies()
        self._model_name = model_name
        self._active: ExtractionStrategy | None = None
        self._acc: dict[str, Any] = {}   # the native message, shape owned by the strategy
        self._text_content: str = ""          # content deltas concatenated (format-agnostic)
        self._finished = False
        self._shown = 0                  # display cursor: chars already shown
        self._held = False               # this round's display veto (reset by add)

    def add(self, chunk: Any) -> None:
        """Feed one raw provider chunk; accumulate into the native message.

        Resolves the wire format on the first chunk and delegates reassembly to it. The
        content delta it returns is appended to the display buffer. Returns nothing --
        what may be *shown* is decided by the driver (via :meth:`hold`) and read via
        :meth:`text`. Resets the per-round display veto (default: flow).
        """
        self._held = False
        if self._active is None:
            self._active = self._resolve(chunk)
        delta = self._active.accumulate(self._acc, chunk)
        if delta:
            self._text_content += delta
        if self._active.is_stream_complete(chunk):
            self._finished = True

    # -- read API -------------------------------------------------------------

    def get_content(self) -> str | None:
        """The assistant-visible text accumulated so far (``None`` if empty)."""
        return self._text_content or None

    def is_finished(self) -> bool:
        """``True`` once the active format signalled the stream's completion."""
        return self._finished

    def as_dict(self) -> dict[str, Any]:
        """The message so far, in the active format's **native** shape.

        Bridges the buffer to the ``str | dict``-based ``ExtractionStrategy`` chain,
        which also serves the non-streaming path. Before any chunk (or after a reset) it
        is the neutral empty assistant message.
        """
        if not self._acc:
            return {"role": "assistant", "content": self._text_content or None}
        return self._acc

    # -- display (driver holds; client reads) ---------------------------------

    def hold(self) -> None:
        """Suppress display for this round -- a tool call may be forming.

        A veto called by the driver inside ``process_llm_response``. If *any* driver in
        a chain holds, :meth:`text` yields nothing this round; the held content is
        released later, once no driver holds it (e.g. the name turns out not to be a
        tool). The veto resets each round (see :meth:`add`), so the default is to flow.
        """
        self._held = True

    def text(self) -> str:
        """The content the client may show now -- empty while held.

        Read *after* ``process_llm_response(buf)``: the driver has had its say. If
        nothing held it, returns the content since it was last shown; if a driver held
        it, returns ``""`` (and signals via its ``DriverResponse``).
        """
        if self._held:
            return ""
        out = self._text_content[self._shown:]
        self._shown = len(self._text_content)
        return out

    # -- lifecycle ------------------------------------------------------------

    def reset(self) -> None:
        """Clear the accumulator to hunt for the next call; keep the wire format.

        Called by the **driver** once it has consumed a call (executed/failed) --
        buffer lifecycle is the driver's concern, not the client's.
        """
        self._acc = {}
        self._text_content = ""
        self._finished = False
        self._shown = 0
        self._held = False

    # -- internals ------------------------------------------------------------

    def _resolve(self, chunk: Any) -> ExtractionStrategy:
        """Pick the wire format that recognises *chunk*, defaulting to the baseline."""
        for strategy in self._strategies:
            if strategy.recognizes(chunk):
                return strategy
        return self._strategies[0]
