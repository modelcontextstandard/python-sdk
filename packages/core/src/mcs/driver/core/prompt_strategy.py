"""PromptStrategy -- Codec that unifies prompt generation and response parsing.

A PromptStrategy defines:
1. How tools are presented to the LLM  (``format_tools``)
2. What call format the LLM should use  (``format_call_example``)
3. How to parse the LLM response back   (``parse_tool_call``)
4. Self-healing regex rules              (loaded from TOML)
5. Retry prompts                         (loaded from TOML)

The default implementation ``JsonPromptStrategy`` uses JSON.
All text that reaches the LLM lives in TOML files, not in Python code.

See MCS Specification Section 10 -- LLM Prompt Patterns.
"""

from __future__ import annotations

import json
import logging
import re
import tomllib
from abc import ABC, abstractmethod
from enum import Enum
from importlib.resources import files as pkg_files
from pathlib import Path
from typing import Any

from .mcs_tool_driver_interface import Tool

logger = logging.getLogger(__name__)


class UnknownToolBehavior(str, Enum):
    """What to do when the LLM calls a tool that is not registered."""
    SILENT = "silent"
    RETRY_WITH_LIST = "retry"


class PromptStrategy(ABC):
    """Abstract codec: encodes prompts, decodes LLM responses.

    Concrete implementations pair a specific format (JSON, XML, ...)
    with matching prompt templates and a parser that understands
    that format.
    """

    unknown_tool_behavior: UnknownToolBehavior = UnknownToolBehavior.SILENT

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
        """Extract ``(tool_name, arguments)`` from LLM output, or ``None``."""

    @abstractmethod
    def retry_no_tool_field(self) -> str:
        """Retry prompt when a JSON object was found but has no tool field."""

    @abstractmethod
    def retry_unknown_tool(self, tool_name: str, available: str) -> str:
        """Retry prompt when the tool name is not in the known set."""

    @abstractmethod
    def retry_execution_failed(self, tool_name: str, error: str) -> str:
        """Retry prompt when tool execution raised an exception."""

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
        self.unknown_tool_behavior = UnknownToolBehavior(
            parsing.get("unknown_tool_behavior", "silent")
        )

        self._healing_rules: list[tuple[str, str]] = [
            (h["pattern"], h["replacement"])
            for h in config.get("healing", [])
        ]

        retry = config.get("retry_prompts", {})
        self._retry_no_tool_field: str = retry.get("no_tool_field", "")
        self._retry_unknown_tool: str = retry.get("unknown_tool", "")
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
        cleaned = self._apply_healing(raw)

        match = re.search(r"\{.*\}", cleaned, re.S)
        if not match:
            return None

        try:
            obj = json.loads(match.group(0))
        except json.JSONDecodeError:
            return None

        tool_name: str | None = None
        for alias in self._tool_field_aliases:
            tool_name = obj.get(alias)
            if tool_name:
                break
        if not tool_name:
            return None

        arguments = obj.get("arguments", {}) or {}
        return tool_name, arguments

    def retry_no_tool_field(self) -> str:
        return self._retry_no_tool_field

    def retry_unknown_tool(self, tool_name: str, available: str) -> str:
        return self._retry_unknown_tool.format(
            tool_name=tool_name, available=available
        )

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
