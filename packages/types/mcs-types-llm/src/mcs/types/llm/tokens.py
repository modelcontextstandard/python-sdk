"""Token estimation -- the *a priori* guess, to be replaced by measurement.

Deciding how much text to send needs a token count before anything has been sent, and at
that moment nobody has one: :class:`~mcs.types.llm.LLMPort` deliberately reports no
tokenizer, because tokenization belongs to the model rather than to the connection.

So the first call is estimated. Every call after it need not be: the response carries
:class:`~mcs.types.llm.TokenUsage` with the backend's own measurement, and comparing that
against this estimate yields the real ratio for *this* model and *this* kind of text.
Callers should calibrate rather than keep guessing -- the constant below is a starting
point, not an answer.

This module has **zero** runtime dependencies.
"""

from __future__ import annotations

#: Characters per token assumed before any measurement exists.
#:
#: Chosen **conservatively**, i.e. lower than the ~4 usually quoted for English prose,
#: because the two ways of being wrong do not cost the same. Underestimating tokens
#: overflows the window: a request is refused, and the caller pays a wasted round trip
#: before it can retry smaller. Overestimating merely produces one more chunk than
#: strictly necessary.
#:
#: The quoted ~4 also only holds for English prose. German compounds, source code, JSON
#: and markup all pack fewer characters into a token, and those are exactly the inputs a
#: document summarizer meets -- so the common case is nearer this figure than the
#: textbook one anyway.
DEFAULT_CHARS_PER_TOKEN = 3.0


def estimate_tokens(text: str, chars_per_token: float = DEFAULT_CHARS_PER_TOKEN) -> int:
    """Estimate how many tokens *text* will occupy.

    An estimate, and callers should treat it as one: budget with headroom and be ready
    for :class:`~mcs.types.llm.ContextWindowExceeded` anyway. After a first call, prefer
    a ratio calibrated from the measured :class:`~mcs.types.llm.TokenUsage` -- pass it as
    *chars_per_token* and this becomes an informed estimate rather than a generic one.
    (The ``LLMSummarizer`` does exactly that automatically, downward only: a measured
    denser ratio replaces the guess, a cheaper one is never drifted into.)
    """
    if chars_per_token <= 0:
        raise ValueError("chars_per_token must be positive")
    return int(len(text) / chars_per_token) + 1
