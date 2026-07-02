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
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from .prompt_strategy import PromptStrategy
    from .mcs_driver_interface import ToolCallRecord

logger = logging.getLogger(__name__)


@dataclass
class ExtractedCall:
    """One runnable tool call found in an LLM response.

    The format-neutral hand-off from :meth:`ExtractionStrategy.extract` to the
    driver: *what* to run (``name`` + parsed ``arguments``) and, for native
    formats, the ``id`` needed to answer the call in the provider's history. A
    message may yield several (native parallel calls); text yields at most one.
    """
    name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    id: str | None = None


def _get(obj: Any, key: str, default: Any = None) -> Any:
    """Read *key* from a dict or as an attribute.

    Streaming chunks arrive as dicts (JSON) or as SDK objects (litellm/OpenAI);
    a format strategy owns that per-SDK access so the buffer never has to.
    """
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _result_text(result: Any) -> str:
    """Render a tool result as the text that goes back to the LLM."""
    return result if isinstance(result, str) else json.dumps(result)


def _message_text(message: Any) -> str:
    """The assistant-visible text of a message (``str`` or ``{"content": ...}``)."""
    if isinstance(message, str):
        return message
    if isinstance(message, dict):
        return message.get("content") or ""
    return ""


class ExtractionStrategy(ABC):
    """Own one tool format: recognise it, reassemble its stream, extract its call.

    The protocol:

    1. **Recognise** -- :meth:`recognizes` inspects a *shape* (an assembled
       message *or* a raw streaming chunk) and returns ``True`` when it belongs
       to this format. Default ``False`` = *"I never recognise -- use me as
       fallback"*.
    2. **Extract** -- :meth:`extract` parses a *complete* message into the list of
       runnable :class:`ExtractedCall` s it carries (native formats may carry
       several in parallel).
    3. **Result history** -- :meth:`result_messages` shapes the executed calls back
       into this format's conversation history (native answers each ``tool_call_id``;
       the default is the plain assistant/system text pair).
    4. **Accumulate** -- :meth:`accumulate` merges one raw streaming chunk into
       the canonical accumulator; :meth:`is_done` reports the format's stream
       completion signal; :meth:`is_forming` reports a call still being assembled.
       Non-streaming strategies inherit the no-op defaults.

    :class:`~mcs.driver.core.ExtractionChain` iterates strategies: the first that
    *recognises* owns the shape exclusively. ``TextExtractionStrategy`` never
    recognises and is the final fallback.
    """

    def recognizes(self, shape: Any) -> bool:
        """Return ``True`` when *shape* (message or chunk) belongs to this format."""
        return False

    @abstractmethod
    def extract(self, message: str | dict) -> list[ExtractedCall]:
        """Return every runnable tool call in a *complete* message (``[]`` if none).

        A format may carry several calls at once (native parallel ``tool_calls``);
        each becomes one :class:`ExtractedCall`. Incomplete or unparseable calls are
        omitted -- only calls the driver can actually run are returned.
        """

    def result_messages(
        self, message: str | dict, records: "list[ToolCallRecord]",
    ) -> list[dict[str, Any]]:
        """Shape executed *records* into this format's conversation history.

        The default is the plain-text shape -- an ``assistant`` echo followed by one
        ``system`` message per result -- which fits text-embedded calls and any
        custom strategy. Native formats override this to answer each call by its
        ``tool_call_id`` (see :class:`_NativeToolCallStrategy`).
        """
        msgs: list[dict[str, Any]] = [
            {"role": "assistant", "content": _message_text(message)}
        ]
        for r in records:
            content = r.error if r.error is not None else _result_text(r.result)
            msgs.append({"role": "system", "content": content})
        return msgs

    def is_forming(self, message: str | dict) -> bool:
        """Return ``True`` when *message* holds a call still being assembled.

        Read mid-stream to decide ``call_pending``: while a call is forming and the
        stream is not done, the driver holds off executing. The default is ``False``
        (a format whose calls never stream in partially); native formats report
        ``True`` while any tool call is present but the batch is not yet complete.
        """
        return False

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

    def extract(self, message: str | dict) -> list[ExtractedCall]:
        text: str | None = None
        if isinstance(message, str):
            text = message
        elif isinstance(message, dict):
            content = message.get("content")
            if isinstance(content, str):
                text = content
        if not text:
            return []
        parsed = self._codec.parse_tool_call(text)
        if parsed is None:
            return []
        name, arguments = parsed
        return [ExtractedCall(name=name, arguments=arguments)]


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

    def extract(self, message: str | dict) -> list[ExtractedCall]:
        if not isinstance(message, dict):
            return []
        tool_calls = message.get("tool_calls")
        if not tool_calls or not isinstance(tool_calls, list):
            return []
        calls: list[ExtractedCall] = []
        for tc in tool_calls:
            call = self._parse_call(tc)
            if call is not None:
                calls.append(call)
        return calls

    @staticmethod
    def _parse_call(tc: Any) -> ExtractedCall | None:
        """Normalise one canonical ``tool_calls[]`` entry, or ``None`` if not runnable."""
        if not isinstance(tc, dict):
            return None
        fn = tc.get("function")
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
                # sends "{}". Not runnable -> omit (streaming keeps buffering).
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

        return ExtractedCall(name=name, arguments=arguments, id=tc.get("id"))

    def result_messages(
        self, message: str | dict, records: "list[ToolCallRecord]",
    ) -> list[dict[str, Any]]:
        """Native history: the assistant echo + one ``role="tool"`` per call.

        OpenAI (and the other native formats) require a tool result for **every**
        ``tool_call`` echoed in the assistant message, keyed by ``tool_call_id`` --
        a ``system`` message does not close a native call. The echo carries only the
        calls this driver ran, so no id is left dangling (foreign/ignored calls are
        another driver's to answer).
        """
        content = message.get("content") if isinstance(message, dict) else None
        assistant: dict[str, Any] = {
            "role": "assistant",
            "content": content,
            "tool_calls": [self._as_tool_call(r) for r in records],
        }
        tool_msgs = [
            {
                "role": "tool",
                "tool_call_id": r.tool_call_id,
                "content": r.error if r.error is not None else _result_text(r.result),
            }
            for r in records
        ]
        return [assistant, *tool_msgs]

    @staticmethod
    def _as_tool_call(r: "ToolCallRecord") -> dict[str, Any]:
        """Rebuild the canonical ``tool_calls[]`` entry from an executed record."""
        return {
            "id": r.tool_call_id,
            "type": "function",
            "function": {"name": r.name, "arguments": json.dumps(r.arguments)},
        }

    def is_forming(self, message: str | dict) -> bool:
        # Any accumulated tool call means the batch is forming; the driver pairs
        # this with the stream's DONE signal to know when it is safe to execute.
        return isinstance(message, dict) and bool(message.get("tool_calls"))


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
