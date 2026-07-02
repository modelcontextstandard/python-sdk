"""ExtractionStrategy -- locate *and* reassemble tool calls in LLM responses.

An ``ExtractionStrategy`` owns the knowledge of **one tool format**. It answers
two questions for that format:

- *"Where is the tool call in this (complete) response?"* -> :meth:`extract`
- *"How do the streaming fragments of this format stitch together?"* ->
  :meth:`accumulate` / :meth:`is_done`

It is deliberately separate from the ``PromptStrategy`` (codec), which answers
*"what text format is a tool call written in?"* -- the codec parametrises the
*text* strategy; a streaming *wire* format is its own strategy subclass.

Concrete implementations:

- ``TextExtractionStrategy`` -- delegates to a ``PromptStrategy`` codec to find a
  tool call embedded in free text (bridge pattern). Non-streaming.
- ``OpenAICompletionExtractionStrategy`` -- OpenAI Chat Completions: assembled
  ``tool_calls[0].function`` and the ``choices[0].delta.tool_calls[]`` stream.
- ``OpenAIResponseExtractionStrategy`` -- OpenAI Responses API: ``function_call``
  items and the ``response.function_call_arguments.delta`` event stream.
- ``AnthropicExtractionStrategy`` -- Anthropic Messages: ``tool_use`` blocks and
  the ``content_block_start`` / ``input_json_delta`` event stream.

The three native strategies **normalise their wire onto the canonical OpenAI
*message* shape** (``{tool_calls:[{function:{name, arguments}}]}``, ``arguments``
a JSON string) and share one :meth:`extract`. This mirrors litellm's proven
architecture -- a per-provider iterator that translates events into OpenAI-shaped
chunks, feeding one generic assembler. See
``packages/core/docs/streaming-tool-formats.md``.
"""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from .prompt_strategy import PromptStrategy

logger = logging.getLogger(__name__)


def _get(obj: Any, key: str, default: Any = None) -> Any:
    """Read *key* from a dict or as an attribute.

    Streaming chunks arrive as dicts (JSON) or as SDK objects (litellm/OpenAI);
    a format strategy owns that per-SDK access so the buffer never has to.
    """
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


class ExtractionStrategy(ABC):
    """Own one tool format: recognise it, reassemble its stream, extract its call.

    The protocol:

    1. **Recognise** -- :meth:`recognizes` inspects a *shape* (an assembled
       message *or* a raw streaming chunk) and returns ``True`` when it belongs
       to this format. Default ``False`` = *"I never recognise -- use me as
       fallback"*.
    2. **Extract** -- :meth:`extract` parses a *complete* message into
       ``(name, arguments)``.
    3. **Accumulate** -- :meth:`accumulate` merges one raw streaming chunk into
       the canonical accumulator; :meth:`is_done` reports the format's stream
       completion signal. Non-streaming strategies inherit the no-op defaults.

    :class:`~mcs.driver.core.ExtractionChain` iterates strategies: the first that
    *recognises* owns the shape exclusively. ``TextExtractionStrategy`` never
    recognises and is the final fallback.
    """

    def recognizes(self, shape: Any) -> bool:
        """Return ``True`` when *shape* (message or chunk) belongs to this format."""
        return False

    @abstractmethod
    def extract(
        self, llm_response: str | dict,
    ) -> tuple[str, dict[str, Any]] | None:
        """Return ``(tool_name, arguments)`` from a complete message, or ``None``."""

    # -- Streaming seam (no-op for non-streaming strategies) -------------------

    def accumulate(self, acc: dict[str, Any], chunk: Any) -> str | None:
        """Merge one raw streaming *chunk* into the canonical accumulator *acc*.

        *acc* is a message dict (``{"role", "content", "tool_calls"}``) mutated
        in place. Returns the **content delta** of this chunk for live display,
        or ``None``. The default does nothing -- only native wire formats
        reassemble structured tool calls.
        """
        return None

    def is_done(self, chunk: Any) -> bool:
        """Return ``True`` when *chunk* carries this format's stream-done signal."""
        return False


class TextExtractionStrategy(ExtractionStrategy):
    """Bridge to the ``PromptStrategy`` codec for text-based responses.

    The strategy itself does not know what format to look for -- it
    delegates entirely to ``codec.parse_tool_call()``, which applies
    healing rules and format-specific parsing (JSON regex, XML, ...).

    Accepts both ``str`` and ``dict`` input.  When a dict is received,
    the ``"content"`` field is extracted and parsed as text.  This
    allows clients to pass a full LLM message dict (e.g.
    ``choices[0].message``) without the strategy needing to know
    about the message envelope.
    """

    def __init__(self, codec: PromptStrategy) -> None:
        self._codec = codec

    def extract(
        self, llm_response: str | dict,
    ) -> tuple[str, dict[str, Any]] | None:
        if isinstance(llm_response, str):
            return self._codec.parse_tool_call(llm_response)
        if isinstance(llm_response, dict):
            content = llm_response.get("content")
            if content and isinstance(content, str):
                return self._codec.parse_tool_call(content)
        return None


class _NativeToolCallStrategy(ExtractionStrategy):
    """Shared base for native tool-call formats.

    Subclasses translate their provider's stream into the **canonical OpenAI
    message shape** via :meth:`accumulate`, so a single :meth:`extract` reads the
    result. State (the accumulator) lives in the buffer; strategies stay
    stateless. :meth:`_slot` grows/returns a tool-call entry by index.
    """

    @staticmethod
    def _slot(acc: dict[str, Any], index: int) -> dict[str, Any]:
        """Return the tool-call entry at *index*, growing the list as needed."""
        calls: list[dict[str, Any]] = acc.setdefault("tool_calls", [])
        while len(calls) <= index:
            calls.append({"type": "function", "function": {"name": "", "arguments": ""}})
        return calls[index]

    def extract(
        self, llm_response: str | dict,
    ) -> tuple[str, dict[str, Any]] | None:
        if not isinstance(llm_response, dict):
            return None

        tool_calls = llm_response.get("tool_calls")
        if not tool_calls or not isinstance(tool_calls, list):
            return None

        first = tool_calls[0]
        if not isinstance(first, dict):
            return None

        fn = first.get("function")
        if not fn or not isinstance(fn, dict):
            return None

        name = fn.get("name")
        if not name or not isinstance(name, str):
            return None

        raw_args = fn.get("arguments", "{}")
        if isinstance(raw_args, str):
            stripped = raw_args.strip()
            if not stripped:
                # Empty string: arguments not streamed yet (the first fragment
                # carries the name; arguments arrive after). A genuine no-arg call
                # sends "{}". Report incomplete so streaming keeps buffering.
                return None
            try:
                arguments = json.loads(stripped)
            except json.JSONDecodeError:
                # Non-empty but unparseable: still streaming or malformed.
                return None
        elif isinstance(raw_args, dict):
            arguments = raw_args
        else:
            arguments = {}

        return name, arguments


class OpenAICompletionExtractionStrategy(_NativeToolCallStrategy):
    """OpenAI **Chat Completions** format.

    Assembled: ``{"tool_calls": [{"function": {"name", "arguments"}}]}`` with
    ``arguments`` a JSON string. Stream: ``choices[0].delta.tool_calls[]``
    fragments keyed by integer ``index`` (name/id once, ``arguments`` string
    fragments concatenated), completion at ``choices[0].finish_reason``.

    Recognises both the assembled message (``"tool_calls"`` key) and a raw
    Completion chunk (``choices``) -- so it serves the driver's extract path and
    the buffer's accumulate path.
    """

    def recognizes(self, shape: Any) -> bool:
        if isinstance(shape, dict):
            return "tool_calls" in shape or "choices" in shape
        return _get(shape, "choices") is not None

    def accumulate(self, acc: dict[str, Any], chunk: Any) -> str | None:
        choices = _get(chunk, "choices")
        delta = _get(choices[0], "delta") if choices else chunk
        if delta is None:
            return None

        content = _get(delta, "content")
        if content:
            acc["content"] = (acc.get("content") or "") + content

        for tc in _get(delta, "tool_calls") or []:
            index = _get(tc, "index", 0) or 0
            entry = self._slot(acc, index)
            tc_id = _get(tc, "id")
            if tc_id:
                entry["id"] = tc_id
            fn = _get(tc, "function")
            if fn is not None:
                name = _get(fn, "name")
                if name:
                    entry["function"]["name"] = name
                args = _get(fn, "arguments")
                if args:
                    entry["function"]["arguments"] += args

        return content or None

    def is_done(self, chunk: Any) -> bool:
        choices = _get(chunk, "choices")
        return bool(choices) and _get(choices[0], "finish_reason") is not None


class OpenAIResponseExtractionStrategy(_NativeToolCallStrategy):
    """OpenAI **Responses API** format.

    Stream of semantically-typed events: ``response.output_item.added`` (a
    ``function_call`` item, carrying ``call_id`` + ``name`` up front),
    ``response.function_call_arguments.delta`` (argument string fragments),
    ``response.output_text.delta`` (content). SLOT = ``output_index``. Completion
    at ``response.completed`` (or per-call ``…arguments.done``). Normalised onto
    the canonical shape and extracted via the shared base.
    """

    def recognizes(self, shape: Any) -> bool:
        etype = _get(shape, "type")
        return isinstance(etype, str) and etype.startswith("response.")

    def accumulate(self, acc: dict[str, Any], chunk: Any) -> str | None:
        etype = _get(chunk, "type")

        if etype == "response.output_text.delta":
            delta = _get(chunk, "delta")
            if delta:
                acc["content"] = (acc.get("content") or "") + delta
            return delta or None

        if etype == "response.output_item.added":
            item = _get(chunk, "item")
            if item is not None and _get(item, "type") == "function_call":
                entry = self._slot(acc, _get(chunk, "output_index", 0) or 0)
                call_id = _get(item, "call_id")
                if call_id:
                    entry["id"] = call_id
                name = _get(item, "name")
                if name:
                    entry["function"]["name"] = name
            return None

        if etype == "response.function_call_arguments.delta":
            entry = self._slot(acc, _get(chunk, "output_index", 0) or 0)
            delta = _get(chunk, "delta")
            if delta:
                entry["function"]["arguments"] += delta
            return None

        return None

    def is_done(self, chunk: Any) -> bool:
        return _get(chunk, "type") in (
            "response.completed",
            "response.function_call_arguments.done",
        )


class AnthropicExtractionStrategy(_NativeToolCallStrategy):
    """Anthropic **Messages** format.

    Stream of SSE events: ``content_block_start`` for a ``tool_use`` block
    (carrying ``id`` + ``name`` once), ``content_block_delta`` with
    ``input_json_delta`` (``partial_json`` argument fragments) or ``text_delta``
    (content). SLOT = ``index``. Completion at ``message_stop``. Normalised onto
    the canonical shape and extracted via the shared base.
    """

    def recognizes(self, shape: Any) -> bool:
        return _get(shape, "type") in {
            "message_start", "content_block_start", "content_block_delta",
            "content_block_stop", "message_delta", "message_stop", "ping",
        }

    def accumulate(self, acc: dict[str, Any], chunk: Any) -> str | None:
        etype = _get(chunk, "type")

        if etype == "content_block_start":
            block = _get(chunk, "content_block")
            if block is not None and _get(block, "type") in ("tool_use", "server_tool_use"):
                entry = self._slot(acc, _get(chunk, "index", 0) or 0)
                block_id = _get(block, "id")
                if block_id:
                    entry["id"] = block_id
                name = _get(block, "name")
                if name:
                    entry["function"]["name"] = name
            return None

        if etype == "content_block_delta":
            delta = _get(chunk, "delta")
            dtype = _get(delta, "type")
            if dtype == "text_delta":
                text = _get(delta, "text")
                if text:
                    acc["content"] = (acc.get("content") or "") + text
                return text or None
            if dtype == "input_json_delta":
                entry = self._slot(acc, _get(chunk, "index", 0) or 0)
                partial = _get(delta, "partial_json")
                if partial:
                    entry["function"]["arguments"] += partial
            return None

        return None

    def is_done(self, chunk: Any) -> bool:
        return _get(chunk, "type") == "message_stop"
