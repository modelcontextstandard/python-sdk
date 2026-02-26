"""ExtractionStrategy -- locate tool calls in LLM responses.

An ``ExtractionStrategy`` answers the question *"Where is the tool call
in this LLM response?"*.  It is deliberately separate from the
``PromptStrategy`` (codec) which answers *"What format is the tool call
in?"*.

Concrete implementations:

- ``TextExtractionStrategy`` -- delegates to a ``PromptStrategy`` codec
  to find a tool call embedded in free text (bridge pattern).
- ``DirectDictExtractionStrategy`` -- reads the MCS simple format
  ``{"tool": ..., "arguments": ...}`` from a dict.
- ``OpenAIExtractionStrategy`` -- reads the OpenAI function-calling
  format from a dict (``tool_calls[0].function``).

Future (documented, not implemented):

- **AnthropicExtractionStrategy** -- reads Anthropic content blocks
  with ``type=tool_use``.
"""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from .prompt_strategy import PromptStrategy

logger = logging.getLogger(__name__)


class ExtractionStrategy(ABC):
    """Locate a tool call in an LLM response."""

    @abstractmethod
    def extract(
        self, llm_response: str | dict,
    ) -> tuple[str, dict[str, Any]] | None:
        """Return ``(tool_name, arguments)`` or ``None`` if not applicable."""


class TextExtractionStrategy(ExtractionStrategy):
    """Bridge to the ``PromptStrategy`` codec for text-based responses.

    The strategy itself does not know what format to look for -- it
    delegates entirely to ``codec.parse_tool_call()``, which applies
    healing rules and format-specific parsing (JSON regex, XML, ...).

    Returns ``None`` immediately when the input is not a ``str``.
    """

    def __init__(self, codec: PromptStrategy) -> None:
        self._codec = codec

    def extract(
        self, llm_response: str | dict,
    ) -> tuple[str, dict[str, Any]] | None:
        if not isinstance(llm_response, str):
            return None
        return self._codec.parse_tool_call(llm_response)


class DirectDictExtractionStrategy(ExtractionStrategy):
    """Extract from the MCS simple dict format ``{"tool": ..., "arguments": ...}``.

    This covers the path used by streaming clients that pre-extract
    native tool calls and pass them as a dict to ``process_llm_response``.

    Returns ``None`` when the input is not a ``dict`` or does not contain
    a ``tool`` key.
    """

    TOOL_ALIASES = ("tool", "name")

    def extract(
        self, llm_response: str | dict,
    ) -> tuple[str, dict[str, Any]] | None:
        if not isinstance(llm_response, dict):
            return None

        tool_name: str | None = None
        for alias in self.TOOL_ALIASES:
            val = llm_response.get(alias)
            if val and isinstance(val, str):
                tool_name = val
                break
        if not tool_name:
            return None

        arguments = llm_response.get("arguments", {}) or {}
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments)
            except json.JSONDecodeError:
                arguments = {}
        return tool_name, arguments


class OpenAIExtractionStrategy(ExtractionStrategy):
    """Extract from the OpenAI function-calling format.

    Expects a dict with::

        {"tool_calls": [{"function": {"name": "...", "arguments": "..."}}]}

    The ``arguments`` value is a JSON string that gets parsed to a dict.

    Returns ``None`` when the input is not a dict or does not match
    the expected structure.
    """

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
            try:
                arguments = json.loads(raw_args)
            except json.JSONDecodeError:
                arguments = {}
        elif isinstance(raw_args, dict):
            arguments = raw_args
        else:
            arguments = {}

        return name, arguments
