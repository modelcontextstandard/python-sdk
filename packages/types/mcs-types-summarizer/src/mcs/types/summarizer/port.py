"""The summarizer port -- query-focused condensation as a capability of its own.

Ask a question of a text that does not fit a context window, and get an answer distilled
from **all** of it. The operation is the same whether the text arrived over HTTP, out of
a PDF or from a transcript: fetching and normalising differ per source, condensation
does not. So it lives here once, and any driver can have it injected -- a
``WebfetchToolDriver`` today, a document or transcript driver tomorrow -- instead of
each growing its own.

The query is **required**, and that is the definition rather than a restriction: this is
query-focused summarization (an established NLP task). "Summarise this" is not a second
operation that would deserve a second method -- it is one query among many, next to
"what does it say about notice periods?" and "list every email address".

This module has **zero** third-party dependencies; it builds on ``mcs-types-llm`` only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from mcs.types.llm import TokenUsage


@dataclass(frozen=True)
class Summary:
    """The condensed answer, and enough about its making to trust it -- or not.

    Attributes
    ----------
    text :
        The answer, distilled from the whole input. An **empty string is a legitimate
        result**: it means the text contained nothing relevant to the query -- which is
        an answer, and a different fact than :attr:`truncated`.
    query :
        What was asked. Carried so the result describes itself: a stored or forwarded
        summary without its query is just prose of unknown intent.
    strategy :
        Which strategy actually ran (``"stuff"``, ``"map_reduce"``, ``"refine"``) --
        *actually*, because ``auto`` may promote and an overflow may force a fallback,
        and the caller should see what happened rather than what was configured.
    chunks :
        How many pieces of the input were read. ``1`` means one model call saw the whole
        text; anything higher states how finely the input had to be cut.
    truncated :
        ``True`` when at least one model answer along the way hit its length cap. This
        is the honesty flag the measurements demanded: a reasoning model can spend an
        entire answer budget thinking and return an empty string with **no error at
        all** -- without this flag, "nothing relevant" and "budget swallowed" would be
        indistinguishable. A truncated summary is not a shorter summary; it is an
        incomplete one.
    usage :
        Measured token cost, summed over every model call this summary took. Fields stay
        ``None`` when no call reported them -- "not reported" and "cost nothing" are
        different facts.
    """

    text: str
    query: str
    strategy: str
    chunks: int
    truncated: bool = False
    usage: TokenUsage = field(default_factory=TokenUsage)


@runtime_checkable
class SummarizerPort(Protocol):
    """Minimal contract for query-focused condensation.

    One method on purpose, mirroring :class:`~mcs.types.llm.LLMPort`: a driver that has
    a summarizer injected asks one thing of it. How the text is split, how many model
    calls it takes and how they are merged is the implementation's business -- the
    caller states the text and the question, and reads the :class:`Summary`.
    """

    def summarize(self, text: str, query: str) -> Summary:
        """Distill *text* into an answer to *query*.

        Raises
        ------
        ValueError
            When *text* or *query* is empty -- there is nothing to condense, or no
            stated intent to condense it under.
        ContextWindowExceeded
            When the caller pinned a strategy that cannot fit the input (e.g.
            ``"stuff"`` with a text larger than the model's window). Implementations
            with a free hand fall back instead of raising.
        """
        ...
