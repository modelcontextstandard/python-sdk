"""DriverBase -- concrete base for hybrid drivers and orchestrators.

Delegates prompt generation and response parsing entirely to a
``PromptStrategy``.  Subclasses only need to implement ``list_tools()``
and ``execute_tool()`` from ``MCSToolDriver``.

All text that reaches the LLM is owned by the strategy, never
hardcoded in this module.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from .mcs_driver_interface import MCSDriver, DriverResponse
from .mcs_tool_driver_interface import MCSToolDriver, Tool
from .prompt_strategy import PromptStrategy, UnknownToolBehavior

logger = logging.getLogger(__name__)


class DriverBase(MCSDriver, MCSToolDriver):
    """Concrete base that wires ``MCSDriver`` methods to a ``PromptStrategy``.

    Subclasses must provide:
    - ``list_tools() -> list[Tool]``
    - ``execute_tool(tool_name, arguments) -> Any``

    Everything else (prompt generation, LLM response parsing, retry
    handling) is inherited and driven by the strategy's TOML config.
    """

    def __init__(
        self,
        *,
        prompt_strategy: PromptStrategy | None = None,
        custom_tool_description: str | None = None,
        custom_system_message: str | None = None,
    ) -> None:
        self._strategy = prompt_strategy or PromptStrategy.default()
        self._custom_tool_description = custom_tool_description
        self._custom_system_message = custom_system_message

    # -- MCSDriver contract ---------------------------------------------------

    def get_function_description(self, model_name: str | None = None) -> str:
        if self._custom_tool_description is not None:
            return self._custom_tool_description
        return self._strategy.format_tools(self.list_tools())

    def get_driver_system_message(self, model_name: str | None = None) -> str:
        if self._custom_system_message is not None:
            return self._custom_system_message
        return self._strategy.system_template.format(
            tools=self.get_function_description(model_name),
            call_example=self._strategy.format_call_example(),
        )

    def process_llm_response(
        self, llm_response: str | dict, *, streaming: bool = False
    ) -> DriverResponse:
        llm_text = (
            llm_response if isinstance(llm_response, str)
            else json.dumps(llm_response)
        )

        parsed = self._strategy.parse_tool_call(llm_text)
        if parsed is None:
            return DriverResponse()

        tool_name, arguments = parsed

        known = {t.name for t in self.list_tools()}
        if tool_name not in known:
            if self._strategy.unknown_tool_behavior == UnknownToolBehavior.RETRY_WITH_LIST:
                available = ", ".join(sorted(known))
                retry = self._strategy.retry_unknown_tool(tool_name, available)
                return DriverResponse(
                    call_failed=True,
                    call_detail=f"No matching tool '{tool_name}' found.",
                    retry_prompt=retry,
                    messages=[
                        {"role": "assistant", "content": llm_text},
                        {"role": "system", "content": retry},
                    ],
                )
            return DriverResponse()

        logger.info("Executing tool: %s", tool_name)

        try:
            result = self.execute_tool(tool_name, arguments)
            result_text = result if isinstance(result, str) else json.dumps(result)
        except Exception as e:
            retry = self._strategy.retry_execution_failed(tool_name, str(e))
            return DriverResponse(
                call_failed=True,
                call_detail=f"Tool '{tool_name}' failed: {e}",
                retry_prompt=retry,
                messages=[
                    {"role": "assistant", "content": llm_text},
                    {"role": "system", "content": retry},
                ],
            )

        return DriverResponse(
            tool_call_result=result_text,
            call_executed=True,
            messages=[
                {"role": "assistant", "content": llm_text},
                {"role": "system", "content": result_text},
            ],
        )
