"""ExtractionChain -- resolve which ExtractionStrategy owns a response shape.

The chain iterates an ordered list of :class:`ExtractionStrategy` instances and returns
the first whose :meth:`~ExtractionStrategy.recognizes` predicate claims the shape --
*forming or complete*. A recognised strategy owns the shape even if its ``extract``
yields nothing *yet*: that "recognised but incomplete" state is what lets streaming tell
"a call is forming" from "plain text".

Order is priority. Native strategies come before the text strategy, so a native envelope
(``tool_calls`` key / block list / event type) always wins over a content-based text
claim. When nothing recognises, ``resolve`` returns ``None`` (plain text, no call). There
is no special fallback slot: the text strategy is a normal strategy that claims its
codec's marker, so adding another codec is just another strategy in the list.

The chain **promotes the last strategy that matched to the front** -- a stateless
optimisation on the assumption that a stream keeps its format (the next chunk/message is
almost always the same wire). It is safe because the shapes are distinguishable (the text
strategy claims only a *string* ``content``; native messages carry structured content),
so promoting one can never make it wrongly claim another format's shape. Dropping the
reordering yields identical results, only slightly slower.

The same chain instances are shared with the :class:`~mcs.driver.core.LLMStreamBuffer`
(via ``SupportsStreaming.new_stream_buffer``): the buffer resolves the *reassembly* axis
on raw chunks, the driver resolves the *extraction* axis on the assembled message -- two
different questions on the one list.
"""

from __future__ import annotations

from .extraction_strategy import ExtractionStrategy


class ExtractionChain:
    """Ordered extraction strategies with shape-based resolution.

    Construct from the driver's strategy list (native first, text last); the driver keeps
    one instance for its extract path.
    """

    def __init__(self, strategies: list[ExtractionStrategy]) -> None:
        self._strategies: list[ExtractionStrategy] = list(strategies)

    def resolve(self, shape: str | dict) -> ExtractionStrategy | None:
        """Return the first strategy that *recognises* ``shape``, or ``None``.

        Strategies are tried in list order (native before text), so an envelope claim
        beats a content claim. The match is promoted to the front for the next call --
        a hit-rate optimisation only; it does not change which strategy wins a given
        shape. ``None`` means no strategy sees a call -- plain text.
        """
        for i, strategy in enumerate(self._strategies):
            if strategy.recognizes(shape):
                if i:
                    self._strategies.insert(0, self._strategies.pop(i))
                return strategy
        return None
