"""ExtractionStrategy -- locate *and* reassemble tool calls in LLM responses.

An ``ExtractionStrategy`` owns the knowledge of **one tool format**, end to end, in
**its own native shape**: it *recognises* that format in a shape (:meth:`recognizes`),
*reassembles* the streaming fragments into its native message (:meth:`accumulate` /
:meth:`is_stream_complete`), *extracts* the complete call(s) from that message (:meth:`extract`),
exposes the message's plain text for the leak fall-through (:meth:`content_text`), and
shapes the executed calls back into the format's conversation *history*
(:meth:`result_messages`). See the class docstring for the full protocol.

Unlike an earlier design, the native strategies do **not** normalise their wire onto a
canonical OpenAI shape. The buffer reassembles each format into the exact message the
provider's SDK returns for ``stream=false`` (OpenAI keeps ``{content, tool_calls}``,
Anthropic keeps its ``content:[{type:"tool_use"}]`` block list, Responses keeps its
``output:[{type:"function_call"}]`` item list) and the strategy reads *its* shape. See
``docs/adr/0001-streaming-extraction-native-reassembly.md`` and
``docs/Reference/streaming-tool-formats.md``.

Concrete implementations:

- ``TextExtractionStrategy`` -- delegates to a ``PromptStrategy`` codec to find a tool
  call embedded in free text (bridge pattern); claims mid-stream via the codec's marker
  so the driver holds display until the call parses. It does not reassemble a wire
  (text content is accumulated by whichever *wire* strategy carries it).
- ``CompletionExtractionStrategy`` -- OpenAI Chat Completions: assembled
  ``{content, tool_calls:[{function:{name, arguments}}]}`` and the
  ``choices[0].delta.tool_calls[]`` stream.
- ``ResponseExtractionStrategy`` -- OpenAI Responses API: an ``output`` item list
  with ``function_call`` items and the ``response.*`` event stream.
- ``MessagesExtractionStrategy`` -- Anthropic Messages: a ``content`` block list with
  ``tool_use`` blocks and the ``content_block_start`` / ``input_json_delta`` event stream.
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
    message may yield several (native parallel calls); text yields several too.

    ``end`` is the offset just past this call's text (including a trailing fence) for a
    *text*-wire call, so the driver can advance the stream buffer past it
    (``buf.consume_through(end)``) and keep the tail -- the next call or trailing prose.
    ``None`` for native calls (their whole message is the batch -> the buffer resets).
    Excluded from equality: it is buffer bookkeeping, not the call's identity.
    """
    name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    id: str | None = None
    end: int | None = field(default=None, compare=False)


@dataclass
class Forming:
    """Whether a tool call is *taking shape* in a message, and its name once known.

    The streaming counterpart of :meth:`ExtractionStrategy.extract`: ``recognizes``
    says *which format* a shape is, ``forming`` says *a call is on its way here* (so the
    driver holds display), and ``extract`` yields it once complete. ``tool_name`` is
    ``None`` until the name has streamed in -- it lets the driver release early when the
    forming call names a tool it does not own. Truthy iff a call is forming.
    """
    forming: bool = False
    tool_name: str | None = None

    def __bool__(self) -> bool:
        return self.forming


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
    """The assistant-visible text of a message (``str`` or ``{"content": <str>}``).

    Returns ``""`` when ``content`` is not a plain string (e.g. an Anthropic block
    list) -- a native message's text is read by that format's :meth:`content_text`,
    never here. This keeps the text strategy from ever claiming a native shape.
    """
    if isinstance(message, str):
        return message
    if isinstance(message, dict):
        content = message.get("content")
        return content if isinstance(content, str) else ""
    return ""


class ExtractionStrategy(ABC):
    """Own one tool format: recognise it, reassemble its stream, extract its call.

    The protocol -- three distinct questions on a message:

    1. **Recognise (which format?)** -- :meth:`recognizes` inspects a *shape* (an
       assembled message *or* a raw streaming chunk) and returns ``True`` when it is
       *this format*, independent of whether a call is present: native formats claim
       their envelope (``tool_calls`` key, event type, block/item list), the text format
       claims plain-text content. Format identification only -- "a call is coming" is
       :meth:`forming`'s job. Default ``False``.
    2. **Forming (is a call coming?)** -- :meth:`forming` returns a :class:`Forming`:
       is a tool call taking shape in this message, and its ``tool_name`` once streamed?
       This is what lets the driver hold display mid-stream (and release early when the
       forming name is a tool it does not own). Default: not forming.
    3. **Extract (the finished call)** -- :meth:`extract` parses a *complete* message
       into the runnable :class:`ExtractedCall` s it carries (native formats may carry
       several in parallel); ``[]`` while still forming *or* when the message is text-only.

    Plus: :meth:`content_text` (the message's plain text, for the leak fall-through),
    :meth:`result_messages` (shape the executed calls back into this format's history),
    and the streaming seam :meth:`accumulate` / :meth:`is_stream_complete` (reassemble the wire;
    non-wire strategies inherit the no-op defaults).

    :class:`~mcs.driver.core.ExtractionChain` iterates strategies in order and the
    first that *recognises* owns the shape. Native strategies come before the text
    strategy, so a native envelope always wins over a plain-text claim.
    """

    #: Does this format deliver calls as a *batch* that grows until the stream's DONE
    #: signal? Native parallel ``tool_calls`` do (execute early and a still-streaming
    #: sibling is stranded), so the driver waits for ``is_finished``. A text-embedded
    #: call is single and self-delimited -- it executes as soon as it parses.
    batched: bool = False

    #: May a message this strategy *claims* hide a tool call in its plain text (a
    #: model that "leaked" the call into the content channel instead of the native
    #: slot)? ``True`` only for envelope formats whose assembled message always carries
    #: their structure even for pure text (Anthropic blocks, Responses items): there a
    #: claimed-but-empty ``extract`` may still hide a leak, so the driver falls through
    #: to the text backup. ``False`` for OpenAI Completions (a leak has no ``tool_calls``
    #: key, so the chain routes it straight to text; a present key is authoritative).
    leaks_into_text: bool = False

    def recognizes(self, shape: Any) -> bool:
        """Return ``True`` when *shape* (message or chunk) is this format.

        Format identification only -- not "a call is present". A native format claims
        its envelope even for a call-free message; the text format claims any plain-text
        content. Whether a call is coming is :meth:`forming`.
        """
        return False

    def forming(self, message: str | dict) -> Forming:
        """Is a tool call taking shape in *message*? Return a :class:`Forming`.

        Truthy while a call for this format is building up (so the driver holds display);
        its ``tool_name`` is filled once the name has streamed in, letting the driver
        release early when the call names a tool it does not own. The default is *not
        forming* (a strategy that carries no streaming call, e.g. a custom one).
        """
        return Forming(False)

    @abstractmethod
    def extract(self, message: str | dict) -> list[ExtractedCall]:
        """Return every runnable tool call in a *complete* message (``[]`` if none).

        A format may carry several calls at once (native parallel calls); each becomes
        one :class:`ExtractedCall`. Incomplete or unparseable calls are omitted -- only
        calls the driver can actually run are returned.
        """

    def content_text(self, message: str | dict) -> str:
        """The plain assistant text of *message* in this format's shape.

        The default reads a string ``content``. Envelope formats whose text lives in a
        structure (Anthropic text blocks, Responses ``output_text`` items) override this.
        Used by the driver's native→text fall-through to hand a leaked call to the backup.
        """
        return _message_text(message)

    def settled_end(self, message: str | dict) -> int:
        """Offset up to which *message* is *settled* -- past every complete object it
        carries (a call or not), before any still-forming block.

        Only meaningful for a text format over a string ``content``: the driver advances
        the buffer past this prefix (``consume_through``) so a settled non-call block
        (an example the model narrated, an unknown format) does not stay at the front and
        anchor the scan on itself. The default is ``0`` (native formats never advance by
        text offset -- they reset the whole message instead).
        """
        return 0

    def result_messages(
        self, message: str | dict, records: "list[ToolCallRecord]",
    ) -> list[dict[str, Any]]:
        """Shape executed *records* into this format's conversation history.

        The default is the plain-text shape -- an ``assistant`` echo followed by one
        ``system`` message per result -- which fits text-embedded calls and any custom
        strategy. Native formats override this to answer each call by its id.
        """
        msgs: list[dict[str, Any]] = [
            {"role": "assistant", "content": _message_text(message)}
        ]
        for r in records:
            content = r.error if r.error is not None else _result_text(r.result)
            msgs.append({"role": "system", "content": content})
        return msgs

    # -- Streaming seam (no-op for non-wire strategies) -----------------------

    def accumulate(self, acc: dict[str, Any], chunk: Any) -> str | None:
        """Merge one raw streaming *chunk* into this format's native accumulator *acc*.

        *acc* is a message dict mutated in place, in **this format's** native shape.
        Returns the **content delta** of this chunk for live display, or ``None``. The
        default does nothing -- only wire formats reassemble a stream.
        """
        return None

    def is_stream_complete(self, chunk: Any) -> bool:
        """Return ``True`` when *chunk* carries this format's stream-done signal."""
        return False


class TextExtractionStrategy(ExtractionStrategy):
    """Bridge to the ``PromptStrategy`` codec for text-based responses.

    The strategy itself does not know what format to look for -- it delegates entirely
    to ``codec.parse_tool_call()``, which applies healing rules and format-specific
    parsing (JSON regex, XML, ...). It reads a call embedded in the message's ``content``
    string; it does **not** reassemble a wire (the content it reads was accumulated by
    whichever *wire* strategy carried the stream). It is also the driver's leak backup:
    the fall-through hands it the plain text of a native message.
    """

    def __init__(self, codec: PromptStrategy) -> None:
        self._codec = codec

    def extract(self, message: str | dict) -> list[ExtractedCall]:
        text = message if isinstance(message, str) else _message_text(message)
        if not text:
            return []
        # All calls in the text, each with its end offset: a message may narrate an
        # example call and then the real one, or carry several real ones. The greedy
        # first-only parse would miss (or, with two objects, fail on) everything after the
        # first; the offset lets the driver advance the buffer past a handled call.
        return [
            ExtractedCall(name=name, arguments=arguments, end=end)
            for name, arguments, end in self._codec.parse_tool_calls(text)
        ]

    def recognizes(self, shape: Any) -> bool:
        """Claim any **plain-text** shape -- a ``str`` or a dict with string ``content``.

        Format identification, not call detection: the text strategy owns text responses
        whether or not a call is embedded (a bare completion, prose, *or* a leaked call).
        Whether a call is coming is :meth:`forming`. Ordered *after* the native
        strategies, so a native envelope (structured ``content``) always wins; because it
        reads only a *string* ``content`` it can never claim a native block/item list.
        """
        if isinstance(shape, str):
            return True
        return isinstance(shape, dict) and isinstance(shape.get("content"), str)

    def forming(self, message: str | dict) -> Forming:
        """A call is forming iff the codec's marker is present; peek its name if streamed."""
        text = _message_text(message)
        if not self._codec.looks_like_call(text):
            return Forming(False)
        return Forming(True, self._codec.peek_tool_name(text))

    def settled_end(self, message: str | dict) -> int:
        text = message if isinstance(message, str) else _message_text(message)
        return self._codec.settled_end(text) if text else 0


class _NativeToolCallStrategy(ExtractionStrategy):
    """Shared base for native tool-call formats.

    Native parallel calls arrive as a growing batch, so :attr:`batched` is ``True`` --
    the driver waits for the DONE signal before executing. Each subclass reassembles and
    reads **its own** native shape; the base only shares argument parsing. State (the
    accumulator) lives in the buffer; strategies stay stateless.
    """

    batched = True

    @staticmethod
    def _parse_args(raw: Any) -> dict[str, Any] | None:
        """Parse streamed arguments; ``None`` when not yet runnable.

        A dict passes through. A JSON string is parsed; an **empty** string means the
        arguments have not streamed yet (the name arrives first) -- not runnable. A
        non-empty but unparseable string is still forming or malformed -- also not
        runnable. A genuine no-argument call sends ``"{}"`` and parses to ``{}``.
        """
        if isinstance(raw, dict):
            return raw
        if isinstance(raw, str):
            stripped = raw.strip()
            if not stripped:
                return None
            try:
                return json.loads(stripped)
            except json.JSONDecodeError:
                return None
        return {}


class CompletionExtractionStrategy(_NativeToolCallStrategy):
    """OpenAI **Chat Completions** format (also litellm's normalised chunk shape).

    Native message: ``{role, content, tool_calls:[{id, type, function:{name,
    arguments}}]}`` with ``arguments`` a JSON string. Stream:
    ``choices[0].delta.tool_calls[]`` fragments keyed by integer ``index`` (name/id
    once, ``arguments`` string fragments concatenated), completion at
    ``choices[0].finish_reason``.

    Recognises both the assembled message (``tool_calls`` key) and a raw Completion
    chunk (``choices``) -- serving the driver's extract path and the buffer's accumulate
    path. A pure-text or *leaked* response has **no** ``tool_calls`` key, so this strategy
    does not claim it and the chain routes it to text (hence ``leaks_into_text`` stays
    ``False``); a present ``tool_calls`` key -- even ``null`` -- is authoritative "no call".
    """

    def recognizes(self, shape: Any) -> bool:
        if isinstance(shape, dict):
            return "tool_calls" in shape or "choices" in shape
        return _get(shape, "choices") is not None

    def forming(self, message: str | dict) -> Forming:
        """Forming once a ``tool_calls`` entry exists; ``tool_name`` from its function name.

        A present-but-``null`` ``tool_calls`` (the false-positive shape) has no entry, so
        it is *not* forming -- the content is an authoritative non-call.
        """
        if not isinstance(message, dict):
            return Forming(False)
        tool_calls = message.get("tool_calls")
        if not tool_calls or not isinstance(tool_calls, list):
            return Forming(False)
        first = tool_calls[0]
        fn = first.get("function") if isinstance(first, dict) else None
        name = fn.get("name") if isinstance(fn, dict) else None
        return Forming(True, name or None)

    def accumulate(self, acc: dict[str, Any], chunk: Any) -> str | None:
        acc.setdefault("role", "assistant")
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
            if not isinstance(tc, dict):
                continue
            fn = tc.get("function")
            if not isinstance(fn, dict):
                continue
            name = fn.get("name")
            if not name or not isinstance(name, str):
                continue
            args = self._parse_args(fn.get("arguments", "{}"))
            if args is None:
                continue
            calls.append(ExtractedCall(name=name, arguments=args, id=tc.get("id")))
        return calls

    def is_stream_complete(self, chunk: Any) -> bool:
        choices = _get(chunk, "choices")
        return bool(choices) and _get(choices[0], "finish_reason") is not None

    def result_messages(
        self, message: str | dict, records: "list[ToolCallRecord]",
    ) -> list[dict[str, Any]]:
        """Native history: the assistant echo + one ``role="tool"`` per call.

        OpenAI requires a tool result for **every** ``tool_call`` echoed in the assistant
        message, keyed by ``tool_call_id`` -- a ``system`` message does not close a native
        call. The echo carries only the calls this driver ran, so no id is left dangling
        (foreign/ignored calls are another driver's to answer).
        """
        content = message.get("content") if isinstance(message, dict) else None
        assistant: dict[str, Any] = {
            "role": "assistant",
            "content": content,
            "tool_calls": [
                {
                    "id": r.tool_call_id,
                    "type": "function",
                    "function": {"name": r.name, "arguments": json.dumps(r.arguments)},
                }
                for r in records
            ],
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


class ResponseExtractionStrategy(_NativeToolCallStrategy):
    """OpenAI **Responses API** format.

    Native message: ``{output:[{type:"message", content:"..."},
    {type:"function_call", call_id, name, arguments}]}`` -- a flat item list. Stream of
    semantically-typed events: ``response.output_item.added`` (a ``function_call`` item,
    carrying ``call_id`` + ``name`` up front), ``response.function_call_arguments.delta``
    (argument string fragments), ``response.output_text.delta`` (content). SLOT =
    ``output_index``. Completion at ``response.completed`` (or per-call
    ``…arguments.done``). Its text lives in ``message`` items, so ``leaks_into_text``.
    """

    leaks_into_text = True

    def recognizes(self, shape: Any) -> bool:
        etype = _get(shape, "type")
        if isinstance(etype, str) and etype.startswith("response."):
            return True
        return isinstance(_get(shape, "output"), list)

    def forming(self, message: str | dict) -> Forming:
        """Forming once a ``function_call`` output item exists; ``tool_name`` from it."""
        if not isinstance(message, dict):
            return Forming(False)
        output = message.get("output")
        if not isinstance(output, list):
            return Forming(False)
        for item in output:
            if isinstance(item, dict) and item.get("type") == "function_call":
                return Forming(True, item.get("name") or None)
        return Forming(False)

    def accumulate(self, acc: dict[str, Any], chunk: Any) -> str | None:
        output: list[Any] = acc.setdefault("output", [])
        etype = _get(chunk, "type")

        if etype == "response.output_text.delta":
            delta = _get(chunk, "delta")
            item = self._item(output, _get(chunk, "output_index", 0) or 0,
                              {"type": "message", "role": "assistant", "content": ""})
            if delta and item.get("type") == "message":
                item["content"] = (item.get("content") or "") + delta
            return delta or None

        if etype == "response.output_item.added":
            it = _get(chunk, "item")
            if _get(it, "type") == "function_call":
                item = self._item(output, _get(chunk, "output_index", 0) or 0,
                                  {"type": "function_call", "arguments": ""})
                call_id = _get(it, "call_id")
                if call_id:
                    item["call_id"] = call_id
                name = _get(it, "name")
                if name:
                    item["name"] = name
            return None

        if etype == "response.function_call_arguments.delta":
            item = self._item(output, _get(chunk, "output_index", 0) or 0,
                              {"type": "function_call", "arguments": ""})
            delta = _get(chunk, "delta")
            if delta:
                item["arguments"] = item.get("arguments", "") + delta
            return None

        return None

    @staticmethod
    def _item(output: list[Any], index: int, default: dict[str, Any]) -> dict[str, Any]:
        """Return the output item at *index*, growing the list as needed."""
        while len(output) <= index:
            output.append(None)
        if output[index] is None:
            output[index] = dict(default)
        return output[index]

    def extract(self, message: str | dict) -> list[ExtractedCall]:
        if not isinstance(message, dict):
            return []
        output = message.get("output")
        if not isinstance(output, list):
            return []
        calls: list[ExtractedCall] = []
        for item in output:
            if not isinstance(item, dict) or item.get("type") != "function_call":
                continue
            name = item.get("name")
            if not name or not isinstance(name, str):
                continue
            args = self._parse_args(item.get("arguments", "{}"))
            if args is None:
                continue
            calls.append(ExtractedCall(name=name, arguments=args, id=item.get("call_id")))
        return calls

    def is_stream_complete(self, chunk: Any) -> bool:
        return _get(chunk, "type") in (
            "response.completed",
            "response.function_call_arguments.done",
        )

    def content_text(self, message: str | dict) -> str:
        if isinstance(message, dict):
            output = message.get("output")
            if isinstance(output, list):
                parts: list[str] = []
                for item in output:
                    if isinstance(item, dict) and item.get("type") == "message":
                        content = item.get("content")
                        if isinstance(content, str):
                            parts.append(content)
                        elif isinstance(content, list):
                            parts.extend(
                                b.get("text", "") for b in content if isinstance(b, dict)
                            )
                return "".join(parts)
        return _message_text(message)

    def result_messages(
        self, message: str | dict, records: "list[ToolCallRecord]",
    ) -> list[dict[str, Any]]:
        """Native Responses history: the ``function_call`` echo + ``function_call_output``.

        The Responses API takes a flat list of input items: each call is echoed as a
        ``function_call`` item and answered by a ``function_call_output`` keyed by the
        same ``call_id``.
        """
        items: list[dict[str, Any]] = []
        for r in records:
            items.append({
                "type": "function_call",
                "call_id": r.tool_call_id,
                "name": r.name,
                "arguments": json.dumps(r.arguments),
            })
            items.append({
                "type": "function_call_output",
                "call_id": r.tool_call_id,
                "output": r.error if r.error is not None else _result_text(r.result),
            })
        return items


class MessagesExtractionStrategy(_NativeToolCallStrategy):
    """The **Messages** format (``/v1/messages``), as introduced by Anthropic.

    Named after the format, not its origin -- like its two siblings here -- because it is
    no longer one vendor's API: gateways and inference providers serve Messages-compatible
    endpoints for open-weight models, so this strategy is not tied to Anthropic.

    Native message: ``{role:"assistant", content:[{type:"text", text},
    {type:"tool_use", id, name, input}]}`` -- a block list. Stream of SSE events:
    ``content_block_start`` for a ``tool_use`` block (carrying ``id`` + ``name`` once),
    ``content_block_delta`` with ``input_json_delta`` (``partial_json`` argument
    fragments) or ``text_delta`` (content). SLOT = ``index``. Completion at
    ``message_stop``. During streaming a ``tool_use`` block accumulates its arguments as
    an ``input_json`` string, parsed to ``input`` by :meth:`extract`. Its text lives in
    ``text`` blocks, so ``leaks_into_text``.
    """

    leaks_into_text = True

    def recognizes(self, shape: Any) -> bool:
        if _get(shape, "type") in {
            "message_start", "content_block_start", "content_block_delta",
            "content_block_stop", "message_delta", "message_stop", "ping",
        }:
            return True
        return isinstance(_get(shape, "content"), list)

    def forming(self, message: str | dict) -> Forming:
        """Forming once a ``tool_use`` block exists; ``tool_name`` from it.

        A leak (a call written into a ``text`` block) is *not* forming here -- there is no
        ``tool_use`` block -- so the driver falls through to the text backup on the blocks'
        text.
        """
        if not isinstance(message, dict):
            return Forming(False)
        content = message.get("content")
        if not isinstance(content, list):
            return Forming(False)
        for block in content:
            if isinstance(block, dict) and block.get("type") in (
                "tool_use", "server_tool_use"
            ):
                return Forming(True, block.get("name") or None)
        return Forming(False)

    def accumulate(self, acc: dict[str, Any], chunk: Any) -> str | None:
        acc.setdefault("role", "assistant")
        blocks: list[Any] = acc.setdefault("content", [])
        etype = _get(chunk, "type")

        if etype == "content_block_start":
            index = _get(chunk, "index", 0) or 0
            block = _get(chunk, "content_block")
            btype = _get(block, "type")
            if btype in ("tool_use", "server_tool_use"):
                self._block(blocks, index, {
                    "type": "tool_use", "id": _get(block, "id"),
                    "name": _get(block, "name"), "input_json": "",
                })
            elif btype == "text":
                self._block(blocks, index, {"type": "text", "text": ""})
            return None

        if etype == "content_block_delta":
            index = _get(chunk, "index", 0) or 0
            delta = _get(chunk, "delta")
            dtype = _get(delta, "type")
            if dtype == "text_delta":
                text = _get(delta, "text")
                block = self._block(blocks, index, {"type": "text", "text": ""})
                if text:
                    block["text"] = (block.get("text") or "") + text
                return text or None
            if dtype == "input_json_delta":
                partial = _get(delta, "partial_json")
                block = self._block(blocks, index, {"type": "tool_use", "input_json": ""})
                if partial:
                    block["input_json"] = block.get("input_json", "") + partial
            return None

        return None

    @staticmethod
    def _block(blocks: list[Any], index: int, default: dict[str, Any]) -> dict[str, Any]:
        """Return the content block at *index*, creating it from *default* if absent."""
        while len(blocks) <= index:
            blocks.append(None)
        if blocks[index] is None:
            blocks[index] = dict(default)
        return blocks[index]

    def extract(self, message: str | dict) -> list[ExtractedCall]:
        if not isinstance(message, dict):
            return []
        content = message.get("content")
        if not isinstance(content, list):
            return []
        calls: list[ExtractedCall] = []
        for block in content:
            if not isinstance(block, dict) or block.get("type") not in (
                "tool_use", "server_tool_use"
            ):
                continue
            name = block.get("name")
            if not name or not isinstance(name, str):
                continue
            raw = block["input"] if "input" in block else block.get("input_json", "")
            args = self._parse_args(raw)
            if args is None:
                continue
            calls.append(ExtractedCall(name=name, arguments=args, id=block.get("id")))
        return calls

    def is_stream_complete(self, chunk: Any) -> bool:
        return _get(chunk, "type") == "message_stop"

    def content_text(self, message: str | dict) -> str:
        if isinstance(message, dict):
            content = message.get("content")
            if isinstance(content, list):
                return "".join(
                    b.get("text", "") for b in content
                    if isinstance(b, dict) and b.get("type") == "text"
                )
        return _message_text(message)

    def result_messages(
        self, message: str | dict, records: "list[ToolCallRecord]",
    ) -> list[dict[str, Any]]:
        """Native Anthropic history: an assistant ``tool_use`` echo + a user ``tool_result``.

        Anthropic answers a call with a ``tool_result`` block (keyed by ``tool_use_id``)
        carried in a **user** message -- not a ``role="tool"`` message. An errored call
        rides back with ``is_error`` so the model can self-heal.
        """
        assistant: dict[str, Any] = {
            "role": "assistant",
            "content": [
                {"type": "tool_use", "id": r.tool_call_id, "name": r.name,
                 "input": r.arguments}
                for r in records
            ],
        }
        results: dict[str, Any] = {
            "role": "user",
            "content": [
                {
                    "type": "tool_result",
                    "tool_use_id": r.tool_call_id,
                    "content": r.error if r.error is not None else _result_text(r.result),
                    **({"is_error": True} if r.error is not None else {}),
                }
                for r in records
            ],
        }
        return [assistant, results]
