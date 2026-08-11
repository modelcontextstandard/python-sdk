"""Errors an :class:`~mcs.types.llm.LLMPort` implementation may raise.

Only one of them is really interesting, and it exists so that callers never have to
read error *prose*.

This module has **zero** runtime dependencies.
"""

from __future__ import annotations


class LLMError(Exception):
    """Base for anything an LLM adapter reports to its caller."""


class ContextWindowExceeded(LLMError):
    """The request did not fit the model's context window.

    Its own type because this is the one failure a caller can actually *act* on: split
    the input and try again. Every backend words it differently -- "maximum context
    length is ... tokens", "prompt is too long", a 400 with a provider-specific code --
    so without a shared type each consumer would end up matching on English error
    strings, which breaks on the next provider or the next wording. The adapter
    translates once; consumers branch on the type.

    That matters more than it looks, because :attr:`~mcs.types.llm.LLMPort.context_window`
    is often ``None``: when the budget cannot be known in advance, overflowing is not an
    edge case but the normal way of finding the limit.

    Attributes
    ----------
    limit :
        The window the backend reported, when it named one -- a free measurement of
        something that was previously unknown, worth remembering on the adapter so the
        same document does not run into the same wall repeatedly.
    requested :
        How many tokens the request came to, when the backend said.
    """

    def __init__(
        self,
        message: str = "The request exceeded the model's context window.",
        *,
        limit: int | None = None,
        requested: int | None = None,
    ) -> None:
        super().__init__(message)
        self.limit = limit
        self.requested = requested
