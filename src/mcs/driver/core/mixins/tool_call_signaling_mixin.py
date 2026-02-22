"""Optional mixin for drivers that support inline tool-call detection during streaming.

When an LLM streams text token-by-token and does not provide native tool-call
events (e.g. older or local models), the client has no way to know whether
the tokens currently being generated are a tool call or regular text.  By the
time the full response is available, the raw JSON has already been displayed.

``ToolCallSignalingMixin`` solves this by giving the driver a lightweight
signaling interface that a streaming client can query on each chunk:

1. ``might_be_tool_call(partial)`` -- fast heuristic on a small token window.
   Returns ``True`` if the accumulated text *could* be the beginning of a
   structured tool call.  The client uses this to pause display output and
   start buffering.

2. ``is_complete_tool_call(text)`` -- checks whether the buffered text is a
   fully parseable tool call that can be passed to ``process_llm_response``.

The mixin is **opt-in**: drivers that only target LLMs with native tool-call
events (OpenAI, Claude, Gemini) do not need it.  Clients detect support via
``isinstance(driver, ToolCallSignalingMixin)``.

The mixin keeps the driver **stateless** -- both methods are pure functions
on the provided text.  All buffering, timeout, and display logic is the
client's responsibility.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class ToolCallSignalingMixin(ABC):
    """Opt-in mixin for inline tool-call detection during streaming.

    A driver implementing this mixin tells streaming clients:
    "I can signal early whether a partial output looks like a tool call."

    The client decides what to do with that signal (buffer, show spinner,
    delay output, etc.).
    """

    @abstractmethod
    def might_be_tool_call(self, partial: str) -> bool:
        """Fast heuristic: could this partial text be the start of a tool call?

        Called by the client on every few accumulated tokens.  Must be cheap
        (no network, no heavy parsing).

        Parameters
        ----------
        partial :
            The accumulated streamed text so far (or a trailing window).

        Returns
        -------
        bool
            ``True`` if the text looks like it *might* become a tool call.
            ``False`` means the client can safely display the text.
        """

    @abstractmethod
    def is_complete_tool_call(self, text: str) -> bool:
        """Check whether the text contains a fully parseable tool call.

        Called by the client once ``might_be_tool_call`` returned ``True``
        and enough tokens have accumulated.  If this returns ``True``, the
        client passes the text to ``process_llm_response`` for execution.

        Parameters
        ----------
        text :
            The full accumulated text buffer.

        Returns
        -------
        bool
            ``True`` if the text contains a complete, parseable tool call.
        """
