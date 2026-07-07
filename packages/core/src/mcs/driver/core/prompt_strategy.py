"""PromptStrategy -- Codec that unifies prompt generation and response parsing.

A PromptStrategy defines:
1. How tools are presented to the LLM  (``format_tools``)
2. What call format the LLM should use  (``format_call_example``)
3. How to parse the LLM response back   (``parse_tool_call``)
4. Self-healing regex rules              (loaded from TOML)
5. Retry prompts                         (loaded from TOML)

The default implementation ``JsonPromptStrategy`` uses JSON.
All text that reaches the LLM lives in TOML files, not in Python code.

See MCS Specification Section 11 -- LLM Prompt Patterns.
"""

from __future__ import annotations

import json
import logging
import re
import tomllib
from abc import ABC, abstractmethod
from importlib.resources import files as pkg_files
from pathlib import Path
from typing import Any

from .mcs_tool_driver_interface import Tool

logger = logging.getLogger(__name__)


class PromptStrategy(ABC):
    """Abstract codec: encodes prompts, decodes LLM responses.

    Concrete implementations pair a specific format (JSON, XML, ...)
    with matching prompt templates and a parser that understands
    that format.
    """

    @property
    @abstractmethod
    def system_template(self) -> str:
        """Template with ``{tools}`` and ``{call_example}`` placeholders."""

    @abstractmethod
    def format_tools(self, tools: list[Tool]) -> str:
        """Serialize ``list[Tool]`` into the target format string."""

    @abstractmethod
    def format_call_example(self) -> str:
        """Return the format example shown to the LLM in the prompt."""

    @abstractmethod
    def parse_tool_call(self, raw: str) -> tuple[str, dict[str, Any]] | None:
        """Extract the *first* ``(tool_name, arguments)`` from LLM output, or ``None``."""

    def parse_tool_calls(self, raw: str) -> list[tuple[str, dict[str, Any], int]]:
        """Every ``(tool_name, arguments, end)`` in *raw*, in order (``[]`` if none).

        A single text message can carry several calls (a model narrating an example call
        and then the real one, or several real ones). ``end`` is the offset just past a
        call's text, so a streaming driver can advance the buffer past a handled call and
        keep the tail. The default wraps :meth:`parse_tool_call` (single call spanning the
        whole text); codecs that read multiple calls override this -- see
        :class:`JsonPromptStrategy`.
        """
        call = self.parse_tool_call(raw)
        return [(call[0], call[1], len(raw))] if call is not None else []

    def settled_end(self, raw: str) -> int:
        """Offset up to which *raw* is settled (complete objects, call or not), so a
        streaming driver can advance past it and parse the next block fresh. The default
        is ``0`` (never advance -- safe for a single-call codec); multi-object codecs
        override this. See :class:`JsonPromptStrategy`."""
        return 0

    @abstractmethod
    def retry_execution_failed(self, tool_name: str, error: str) -> str:
        """Retry prompt when tool execution raised an exception."""

    # -- Streaming (recognise a call taking shape) ----------------------------

    def looks_like_call(self, text: str) -> bool:
        """Return ``True`` when *text* looks like a call in this codec's format.

        The text ``ExtractionStrategy`` uses this in ``recognizes`` to *claim* a
        forming (or complete) call mid-stream, so the driver holds display until the
        stream is done and then parses. It starts conservatively (only on a real
        marker) and releases fast (a non-tool JSON, a foreign fence language). The
        default never claims -- codecs that embed calls in text override it.
        """
        return False

    def peek_tool_name(self, text: str) -> str | None:
        """The candidate tool name in a partial call, or ``None`` if not yet known.

        Lets the driver release a forming call early when its name is not one of the
        driver's tools. The default returns ``None`` (no early release)."""
        return None

    # -- Factory methods ------------------------------------------------------

    @classmethod
    def default(cls) -> PromptStrategy:
        """Return the built-in ``JsonPromptStrategy`` with package defaults."""
        return JsonPromptStrategy.from_defaults()

    @classmethod
    def from_toml(cls, path: str | Path) -> PromptStrategy:
        """Load a ``JsonPromptStrategy`` from a TOML file."""
        return JsonPromptStrategy.from_toml_file(path)


# ---------------------------------------------------------------------------
#  JsonPromptStrategy -- the default codec
# ---------------------------------------------------------------------------


class JsonPromptStrategy(PromptStrategy):
    """JSON-based tool-call codec.  All prompt text comes from config."""

    def __init__(self, config: dict[str, Any]) -> None:
        sm = config.get("system_message", {})
        self._system_template: str = sm.get("template", "")

        ce = config.get("call_example", {})
        self._call_example: str = ce.get("example", "")

        parsing = config.get("parsing", {})
        self._tool_field_aliases: tuple[str, ...] = tuple(
            parsing.get("tool_field_aliases", ("tool", "name"))
        )

        self._healing_rules: list[tuple[str, str]] = [
            (h["pattern"], h["replacement"])
            for h in config.get("healing", [])
        ]

        retry = config.get("retry_prompts", {})
        self._retry_execution_failed: str = retry.get("execution_failed", "")

    # -- Factory helpers ------------------------------------------------------

    @classmethod
    def from_defaults(cls) -> JsonPromptStrategy:
        """Load the package-bundled ``prompts/default_json.toml``."""
        toml_bytes = (
            pkg_files("mcs.driver.core")
            .joinpath("prompts", "default_json.toml")
            .read_bytes()
        )
        config = tomllib.loads(toml_bytes.decode("utf-8"))
        return cls(config)

    @classmethod
    def from_toml_file(cls, path: str | Path) -> JsonPromptStrategy:
        """Load from an arbitrary TOML path."""
        with open(path, "rb") as f:
            config = tomllib.load(f)
        return cls(config)

    # -- PromptStrategy ABC ---------------------------------------------------

    @property
    def system_template(self) -> str:
        return self._system_template

    def format_call_example(self) -> str:
        return self._call_example

    def format_tools(self, tools: list[Tool]) -> str:
        schema: list[dict[str, Any]] = []
        for t in tools:
            properties: dict[str, Any] = {}
            required: list[str] = []
            for p in t.parameters:
                prop = dict(p.schema) if p.schema else {"type": "string"}
                if p.description:
                    prop["description"] = p.description
                properties[p.name] = prop
                if p.required:
                    required.append(p.name)

            entry: dict[str, Any] = {
                "name": t.name,
                "description": t.description,
                "parameters": {
                    "type": "object",
                    "properties": properties,
                },
            }
            if required:
                entry["parameters"]["required"] = required
            schema.append(entry)

        return json.dumps({"tools": schema}, indent=2)

    def parse_tool_call(self, raw: str) -> tuple[str, dict[str, Any]] | None:
        """The *first* call in *raw* (or ``None``). Delegates to :meth:`parse_tool_calls`."""
        calls = self.parse_tool_calls(raw)
        return (calls[0][0], calls[0][1]) if calls else None

    def parse_tool_calls(self, raw: str) -> list[tuple[str, dict[str, Any], int]]:
        # Only the settled objects that ARE calls (a tool alias). Non-call objects are
        # dropped here but still counted by settled_end, so the driver advances past them.
        return [(n, a, e) for (n, a, e) in self._scan(raw) if n is not None]

    def settled_end(self, raw: str) -> int:
        """Offset up to which *raw* is settled -- past every *complete* top-level object
        (call or not) and its fence, before any still-forming block.

        The driver drops this prefix (``buf.consume_through``) so each successive ``{…}``
        is parsed fresh: a settled *non-call* (a model narrating an example, an unknown
        format like ``recipient_name``) would otherwise stay at the front and anchor the
        scan on itself, hiding the block after it.
        """
        scanned = self._scan(raw)
        return scanned[-1][2] if scanned else 0

    def _scan(self, raw: str) -> list[tuple[str | None, dict[str, Any], int]]:
        """Every complete top-level object in *raw*, as ``(name | None, arguments, end)``.

        ``name`` is ``None`` for a JSON object that is not a call. ``end`` is the offset
        just past the object *and* an immediately-following closing fence. Only the region
        *before* a still-open fence is scanned -- an object inside an unclosed ``` is not
        settled yet (parsing it would execute before the fence arrives and orphan it).
        """
        # Restrict to the region before any still-open fence.
        region = raw if raw.count("```") % 2 == 0 else raw[: raw.rfind("```")]
        out: list[tuple[str | None, dict[str, Any], int]] = []
        for obj_str, _start, obj_end in self._iter_json_objects(region):
            try:
                obj = json.loads(self._apply_healing(obj_str))
            except json.JSONDecodeError:
                continue                                   # malformed -> not a settled object
            if not isinstance(obj, dict):
                continue
            name: str | None = None
            for alias in self._tool_field_aliases:
                name = obj.get(alias)
                if name:
                    break
            end = obj_end                                  # include a trailing closing fence
            fence = re.match(r"\s*```", raw[obj_end:])
            if fence is not None:
                end = obj_end + fence.end()
            out.append((name or None, obj.get("arguments", {}) or {}, end))
        return out

    @staticmethod
    def _iter_json_objects(text: str):
        """Yield ``(substring, start, end)`` for each **top-level balanced** ``{…}``.

        A brace scanner (string- and escape-aware) over the *raw* text, so the offsets
        line up with what the buffer holds and several calls in one message are found
        individually -- unlike a greedy ``\\{.*\\}``, which spans from the first ``{`` to
        the *last* ``}`` and so fails to parse when two objects are present.
        """
        depth = 0
        start = -1
        in_str = False
        esc = False
        for i, ch in enumerate(text):
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == "{":
                if depth == 0:
                    start = i
                depth += 1
            elif ch == "}" and depth > 0:
                depth -= 1
                if depth == 0 and start >= 0:
                    yield text[start:i + 1], start, i + 1
                    start = -1

    def looks_like_call(self, text: str) -> bool:
        # Detect on the *raw* text: the fence itself is the signal, and healing would
        # strip it (that is healing's job -- to remove it before the final parse).
        if not text:
            return False

        # Outer marker: a fenced block. Its language tag is a fast release signal --
        # ```python / ```bash is code to *show*, only ``` / ```json can be our call.
        fence = re.search(r"```[ \t]*([A-Za-z0-9_+-]*)", text)
        if fence is not None:
            lang = fence.group(1).lower()
            if lang and lang != "json":
                return False
            after = text[fence.end():].lstrip()
            if not after:
                return True                                # fence open, nothing after yet -> forming
            if not after.startswith("{"):
                return False                               # ```json but not an object -> data/code block
            obj = after
        else:
            brace = text.find("{")                         # bare call may follow prose
            if brace < 0:
                return False
            obj = text[brace:]

        # Inner marker: the object must open with a string key that is a tool alias.
        key = re.match(r'\{\s*"([^"]+)"\s*:', obj)
        if key is None:
            # First key not fully streamed. Keep claiming only while it *could* still be
            # a string-keyed object ('{', '{ ', '{"', '{"partialkey'); '{123' / '{foo'
            # can never be our call -> release immediately.
            return bool(re.match(r'\{\s*("[^"]*)?$', obj))
        return key.group(1) in self._tool_field_aliases

    def peek_tool_name(self, text: str) -> str | None:
        """The tool name in a (partial) call, once it has fully streamed in, else None.

        Lets the driver release a forming call early when the name is not one of its
        tools (a model *explaining* a call rather than making one) instead of holding
        the whole object. Regex/config-driven like the rest of the codec.
        """
        aliases = "|".join(re.escape(a) for a in self._tool_field_aliases)
        m = re.search(rf'"(?:{aliases})"\s*:\s*"([^"]+)"', text)
        return m.group(1) if m else None

    def retry_execution_failed(self, tool_name: str, error: str) -> str:
        return self._retry_execution_failed.format(
            tool_name=tool_name, error=error
        )

    # -- Healing --------------------------------------------------------------

    def _apply_healing(self, raw: str) -> str:
        for pattern, replacement in self._healing_rules:
            try:
                raw = re.sub(pattern, replacement, raw)
            except re.error as e:
                logger.warning("Invalid healing regex %r: %s", pattern, e)
        return raw
