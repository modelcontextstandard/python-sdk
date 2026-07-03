"""ExtractionChain -- resolve which ExtractionStrategy owns a response shape.

The chain iterates an ordered list of :class:`ExtractionStrategy` instances and
returns the first whose :meth:`~ExtractionStrategy.recognizes` predicate claims the
shape -- *forming or complete*. A recognised strategy owns the shape even if its
``extract`` yields nothing *yet*: that "recognised but incomplete" state is what
lets streaming tell "a call is forming" from "plain text".

Order is priority. Native strategies come before the text strategy, so a native
envelope (``tool_calls`` key / event type) always wins over a content-based text
claim -- the native call is already committed and content is never second-guessed.
When nothing recognises, ``resolve`` returns ``None`` (plain text, no call). There
is no special fallback slot: the text strategy is a normal strategy that claims its
codec's marker, so adding another codec is just another strategy in the list.

The streaming buffer (:class:`~mcs.driver.core.LLMStreamBuffer`) does its own,
simpler resolution over the *native wire* formats and is not bound to any driver's
chain -- reassembly is an LLM/SDK concern, identical for every driver.
"""

from __future__ import annotations

from .extraction_strategy import ExtractionStrategy


class ExtractionChain:
    """Ordered extraction strategies with shape-based resolution.

    Construct from the driver's strategy list (native first, text last); the driver
    keeps one instance for its extract path.
    """

    def __init__(self, strategies: list[ExtractionStrategy]) -> None:
        self._strategies: list[ExtractionStrategy] = list(strategies)

    def resolve(self, shape: str | dict) -> ExtractionStrategy | None:
        """Return the first strategy that *recognises* ``shape``, or ``None``.

        Strategies are tried in list order (native before text), so an envelope
        claim beats a content claim. ``None`` means no strategy sees a call --
        plain text.
        """
        for strategy in self._strategies:
            if strategy.recognizes(shape):
                return strategy
        return None
