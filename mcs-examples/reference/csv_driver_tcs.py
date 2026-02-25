"""CSV driver with ToolCallSignalingMixin.

This is a copy of ``csv_driver.py`` extended with
``ToolCallSignalingMixin`` to demonstrate inline tool-call detection
during streaming.  In production you would add the mixin directly to
your driver -- the separation here keeps the base example simple.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from mcs.driver.core import (
    DriverBinding, DriverMeta, DriverResponse, MCSDriver, MCSToolDriver,
    Tool
)
from mcs.driver.core.mixins import ToolCallSignalingMixin

from csv_tooldriver import CsvToolDriver
from localfs_fs_adapter import LocalFsAdapter


@dataclass(frozen=True)
class _CsvTcsDriverMeta(DriverMeta):
    id: str = "b8c3e5f1-4d9a-4b2e-a7c6-9f1d3e5a8b2c"
    name: str = "CSV Driver (TCS)"
    version: str = "0.1.0"
    bindings: tuple[DriverBinding, ...] = (
        DriverBinding(capability="csv", adapter="*", spec_format="Custom"),
    )
    supported_llms: tuple[str, ...] | None = ("*",)
    capabilities: tuple[str, ...] = ()


class CsvDriverTcs(MCSDriver, MCSToolDriver, ToolCallSignalingMixin):
    """CSV driver with streaming tool-call signaling."""

    meta: DriverMeta = _CsvTcsDriverMeta()

    TOOL_CALL_OPENERS = ("{", "```")

    def __init__(self, base_dir: str) -> None:
        self._tooldriver = CsvToolDriver(LocalFsAdapter(base_dir))

    # -- ToolCallSignalingMixin -----------------------------------------------

    def might_be_tool_call(self, partial: str) -> bool:
        stripped = partial.strip()
        if not stripped:
            return False
        for opener in self.TOOL_CALL_OPENERS:
            if stripped.startswith(opener):
                return True
            if opener.startswith(stripped):
                return True
        return False

    def is_complete_tool_call(self, text: str) -> bool:
        payload = self._extract_json_obj(text)
        if payload is None:
            return False
        return "tool" in payload

    # -- MCSToolDriver --------------------------------------------------------

    def list_tools(self) -> list[Tool]:
        return self._tooldriver.list_tools()

    def execute_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        return self._tooldriver.execute_tool(tool_name, arguments)

    # -- MCSDriver ------------------------------------------------------------

    def get_function_description(self, model_name: str | None = None) -> str:
        tools_payload: list[dict[str, Any]] = []
        for tool in self._tooldriver.list_tools():
            tools_payload.append(
                {
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": [
                        {
                            "name": p.name,
                            "description": p.description,
                            "required": p.required,
                            "schema": p.schema,
                        }
                        for p in tool.parameters
                    ],
                }
            )
        return json.dumps({"tools": tools_payload}, indent=2, ensure_ascii=False)

    def get_driver_system_message(self, model_name: str | None = None) -> str:
        return (
            "You can use the following CSV tools. If a tool is needed, answer ONLY as JSON:\n"
            '{"tool":"tool_name","arguments":{"arg":"value"}}\n\n'
            f"{self.get_function_description(model_name)}"
        )

    def process_llm_response(self, llm_response: str | dict, *, streaming: bool = False) -> DriverResponse:
        llm_text = llm_response if isinstance(llm_response, str) else json.dumps(llm_response)

        payload = self._extract_json_obj(llm_text)
        if payload is None:
            return DriverResponse()

        tool_name = payload.get("tool")
        arguments = payload.get("arguments", {})
        if not tool_name:
            retry = "Return exactly one JSON object with fields: tool and arguments."
            return DriverResponse(
                call_failed=True,
                call_detail="Tool field is missing.",
                retry_prompt=retry,
                messages=[
                    {"role": "assistant", "content": llm_text},
                    {"role": "system", "content": retry},
                ],
            )

        try:
            result = self._tooldriver.execute_tool(tool_name, arguments)
            return DriverResponse(
                tool_call_result=result,
                call_executed=True,
                messages=[
                    {"role": "assistant", "content": llm_text},
                    {"role": "system", "content": str(result)},
                ],
            )
        except Exception as exc:
            retry = "Check argument names and value types, then retry with valid JSON."
            return DriverResponse(
                call_failed=True,
                call_detail=f"Tool execution failed: {exc}",
                retry_prompt=retry,
                messages=[
                    {"role": "assistant", "content": llm_text},
                    {"role": "system", "content": retry},
                ],
            )

    @staticmethod
    def _extract_json_obj(raw: str) -> dict[str, Any] | None:
        cleaned = raw.strip()
        if cleaned.startswith("```"):
            cleaned = re.sub(r"^```[^\n]*\n", "", cleaned)
            cleaned = re.sub(r"\n```$", "", cleaned)
        match = re.search(r"\{.*\}", cleaned, re.S)
        if not match:
            return None
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            return None
