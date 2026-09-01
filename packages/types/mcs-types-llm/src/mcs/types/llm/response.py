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

    The names follow the **vendor-neutral vocabulary**: the Responses API, the Messages
    API and OpenTelemetry's GenAI conventions all say input/output, and OTel has
    deprecated prompt/completion outright -- only the oldest wire (Chat Completions)
    still spells them the old way. Each adapter translates its wire's spelling here,
    once, so consumers never meet a dialect.

    Attributes
    ----------
    input :
        Tokens the request occupied -- **everything that went in, cached tokens
        included**. The semantic is pinned here because the wires disagree: OpenAI's
        ``prompt_tokens`` includes cached tokens, Anthropic's ``input_tokens`` excludes
        its cache fields -- an adapter over the latter sums before reporting. The
        interesting field for budgeting: the true size of what was just sent, against
        which an estimate can be calibrated.
    output :
        Tokens the answer occupied -- **including** any the model spent thinking.
    total :
        Both together, as reported. Not derived by MCS -- if a backend states it, it is
        the backend's arithmetic that counts.
    reasoning :
        Of :attr:`output`, how many went into reasoning the caller never sees. The
        field exists because the gap it measures is a trap: ask a reasoning model for a
        summary with a modest answer budget and the thinking can consume all of it,
        leaving an *empty* answer and ``finish_reason="length"`` -- no error, no text.
        ``None`` where the backend does not break it down (most do not).
    cache_read :
        Of :attr:`input`, how many were served from a prompt cache (discounted where
        priced). Cost information rather than budget information: cached tokens still
        occupy the window.
    cache_write :
        Of :attr:`input`, how many were *written* to a prompt cache this call --
        billed at a premium where the concept exists (Anthropic prices 1.25x/2x by
        cache TTL), which is why cost accounting needs it separate. The Chat
        Completions wire has no such field and honestly reports ``None``; gateways
        that surface it top-level (``cache_creation_input_tokens``) are read.
    """

    input: int | None = None
    output: int | None = None
    total: int | None = None
    reasoning: int | None = None
    cache_read: int | None = None
    cache_write: int | None = None


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
