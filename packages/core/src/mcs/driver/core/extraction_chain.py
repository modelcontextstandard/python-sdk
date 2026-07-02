"""ExtractionChain -- resolve which ExtractionStrategy owns a response shape.

The chain iterates an ordered list of :class:`ExtractionStrategy` instances and
returns the first one whose :meth:`~ExtractionStrategy.recognizes` predicate
claims the response's *shape* (e.g. the ``"tool_calls"`` key for OpenAI). The
first recogniser owns the response exclusively.

This resolution used to live inside ``BaseDriver._extract``; it was lifted out so
the driver's chain (with its preferred-strategy cache) is one small, testable
object. The driver resolves a *complete* message, then calls ``extract`` on the
winner (detection). ``TextExtractionStrategy`` never recognises anything; it is
the fallback, reached via :attr:`text_fallback` when no strategy claims the shape.

The streaming buffer (:class:`~mcs.driver.core.LLMStreamBuffer`) does its own,
simpler resolution over the *native wire* formats and is not bound to any driver's
chain -- reassembly is an LLM/SDK concern, identical for every driver.
"""

from __future__ import annotations

from .extraction_strategy import ExtractionStrategy, TextExtractionStrategy


class ExtractionChain:
    """Ordered extraction strategies with shape-based resolution and a cache.

    Construct from the driver's strategy list; the driver keeps one instance for
    its ``extract`` path. The preferred-strategy cache promotes the last winner to
    the front (an optimisation with no effect on the result).
    """

    def __init__(self, strategies: list[ExtractionStrategy]) -> None:
        self._strategies: list[ExtractionStrategy] = list(strategies)
        self._preferred: ExtractionStrategy | None = None
        self._text_fallback: TextExtractionStrategy | None = next(
            (s for s in self._strategies if isinstance(s, TextExtractionStrategy)),
            None,
        )

    @property
    def text_fallback(self) -> TextExtractionStrategy | None:
        """The chain's fallback strategy, or ``None`` -- never returned by :meth:`resolve`."""
        return self._text_fallback

    def resolve(self, shape: str | dict) -> ExtractionStrategy | None:
        """Return the first strategy that *recognises* ``shape``, or ``None``.

        Non-text strategies are tried in order, the last winner promoted to the
        front on the next call (a cache that only affects speed, not the result).
        A recognised strategy owns the shape even if its ``extract`` /
        ``accumulate`` yields nothing *yet* -- that "recognised but incomplete"
        state is what lets streaming tell "keep buffering" from "plain text".

        ``TextExtractionStrategy`` is skipped here; it is the fallback exposed via
        :attr:`text_fallback`, used only when nothing claims the shape.

        .. note::

           Recognition relies on the response *shape* (e.g. a ``"tool_calls"``
           key). This covers >99% of cases; the known edge case is a
           native-tool-capable model called **without** ``tools`` that emits JSON
           in ``content`` resembling a text tool call.
        """
        ordered = self._strategies
        if self._preferred is not None and self._preferred in ordered:
            ordered = [self._preferred] + [
                s for s in ordered if s is not self._preferred
            ]

        for strategy in ordered:
            if isinstance(strategy, TextExtractionStrategy):
                continue
            if strategy.recognizes(shape):
                self._preferred = strategy
                return strategy
        return None
