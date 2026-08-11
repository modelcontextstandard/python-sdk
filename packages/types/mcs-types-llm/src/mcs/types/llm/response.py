"""What one call to a model produced -- text, and what it cost.

The text alone would be enough to *use* an answer. It is not enough to **plan the next
one**, and planning is the whole job of a component that hands a long document to a small
model: how much fits, how much did that chunk really cost, was the answer cut off.

All of it arrives with the response anyway. Every Chat Completions backend returns a
``usage`` block, so these are **measured** token counts from the model's own tokenizer --
exact, free, and better than any estimate an adapter could compute. A caller that
compares them against :func:`~mcs.types.llm.estimate_tokens` learns the real ratio for
*this* model and *this* kind of text after a single call, and stops guessing.

This module has **zero** runtime dependencies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class TokenUsage:
    """Measured token counts for one call. Every field may be ``None``.

    ``None`` means the backend did not report it -- not zero. The distinction matters:
    a caller calibrating its estimate must skip an unreported call, not record it as
    having cost nothing.

    Attributes
    ----------
    prompt :
        Tokens the input occupied. The interesting one for budgeting: it is the true
        size of what was just sent, against which an estimate can be calibrated.
    completion :
        Tokens the answer occupied -- **including** any the model spent thinking.
    total :
        Both together, as reported. Not derived by MCS -- if a backend states it, it is
        the backend's arithmetic that counts.
    reasoning :
        Of :attr:`completion`, how many went into reasoning the caller never sees. The
        field exists because the gap it measures is a trap: ask a reasoning model for a
        summary with a modest answer budget and the thinking can consume all of it,
        leaving an *empty* answer and ``finish_reason="length"`` -- no error, no text.
        ``None`` where the backend does not break it down (most do not).
    cached :
        Of :attr:`prompt`, how many were served from a prompt cache. Cost information
        rather than budget information: cached tokens still occupy the window.
    """

    prompt: int | None = None
    completion: int | None = None
    total: int | None = None
    reasoning: int | None = None
    cached: int | None = None


@dataclass(frozen=True)
class LLMResponse:
    """One model answer.

    Attributes
    ----------
    text :
        The assistant's text. Empty string is a legitimate answer; a model that produced
        no text at all is an error, not an empty response.
    usage :
        What the call cost, as measured by the backend.
    finish_reason :
        Why generation stopped, as the backend named it (``"stop"``, ``"length"``, ...).
        Carried rather than interpreted, because the vocabulary is not standardised --
        except for :attr:`truncated`, which is worth the one interpretation.
    model :
        Which model actually answered. Not necessarily the one requested: a gateway may
        route elsewhere, and a caller recording measurements needs to know what it
        measured.
    meta :
        Backend-specific extras, so a richer response loses nothing while the fields
        above stay predictable. Adapters put the untouched ``usage`` block here, and any
        reasoning *text* a backend exposes outside the standard shape.
    """

    text: str
    usage: TokenUsage = field(default_factory=TokenUsage)
    finish_reason: str | None = None
    model: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def truncated(self) -> bool:
        """``True`` when generation stopped at the length limit rather than finishing.

        The one finish reason worth interpreting here, because it changes what the text
        *means*: a summary cut off mid-sentence is not a shorter summary, it is an
        incomplete one, and a caller that merges several of them needs to know.
        """
        return self.finish_reason == "length"
