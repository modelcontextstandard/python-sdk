"""MCS Basic Orchestrator.

This module defines a basic orchestrator for the Model Context Standard (MCS),
designed to aggregate multiple `MCSToolDriver` instances. It presents a unified
interface to a Language Model (LLM), allowing the LLM to discover and
execute tools managed by various underlying drivers.

Based on an extended MCS Driver Contract, this orchestrator abstracts
the complexities of multiple tool sources into a single, cohesive unit.

Key Responsibilities:
1.  **Tool Aggregation**: Collects and consolidates tools from all registered `MCSToolDriver`s.
2.  **LLM Function Description Generation**: Creates a comprehensive, LLM-readable
    description of all available tools for function-calling.
3.  **LLM System Message Generation**: Formulates a system prompt to guide the LLM
    on how to use the available tools and format its responses.
4.  **Tool Execution Dispatch**: Parses LLM responses for tool calls and dispatches
    them to the appropriate `MCSToolDriver` for execution.

This orchestrator enables flexible integration of diverse toolsets without requiring
the LLM or the client application to manage individual drivers.

"""

from typing import Any, List, Optional
from abc import ABC
import json
import re
import logging

from . import MCSDriver, MCSToolDriver, Tool, DriverMeta, DriverBinding, DriverResponse

logger = logging.getLogger(__name__)


class BasicOrchestrator(MCSDriver, ABC):
    """A simple orchestrator that aggregates multiple ToolDrivers and presents them uniformly to the LLM.

    This class acts as an adapter, combining the capabilities of several `MCSToolDriver` instances
    into a single `MCSDriver` interface, making it easier for a Language Model (LLM) to
    discover and interact with a broad set of tools.
    """

    def __init__(self, drivers: List[MCSToolDriver]):
        """
        Initializes the BasicOrchestrator with a list of MCSToolDriver instances.

        It constructs its own `DriverMeta` by aggregating the bindings from all
        provided drivers and setting default capabilities.

        Parameters
        ----------
        drivers : List[MCSToolDriver]
            A list of initialized `MCSToolDriver` instances that this orchestrator will manage.
        """
        self.drivers = drivers
        self.meta = DriverMeta(
            id="a218ad5e-5d05-4ff3-979c-9eb9e49a2d3c",
            name="Basic Orchestrator",
            version="1.0.0",
            bindings=tuple(binding for driver in drivers for binding in driver.meta.bindings),
            supported_llms=("*",),
            capabilities=()
        )
        logger.info(f"BasicOrchestrator initialized with {len(drivers)} drivers.")
        for driver in drivers:
            logger.debug(f"Loaded driver: {driver.meta.name} (ID: {driver.meta.id})")

    def _collect_tools(self) -> List[Tool]:
        """
        Collects and consolidates all tools from the aggregated `MCSToolDriver` instances.

        Returns
        -------
        List[Tool]
            A flattened list of all `Tool` objects provided by the underlying drivers.
        """
        logger.info("Collecting tools from all registered drivers.")
        tools = []
        for driver in self.drivers:
            driver_tools = driver.list_tools()
            logger.debug(f"Found {len(driver_tools)} tools in driver '{driver.meta.name}'.")
            tools.extend(driver_tools)
        logger.info(f"Total tools collected: {len(tools)}.")
        return tools

    def get_function_description(self, model_name: Optional[str] = None) -> str:
        """
        Generates a comprehensive, LLM-readable description of all aggregated tools.

        Parameters
        ----------
        model_name : Optional[str]
            An optional name of the target LLM.

        Returns
        -------
        str
            A string containing the formatted descriptions of all tools, suitable
            for LLM consumption.
        """
        logger.info("Generating function descriptions for the LLM.")
        tools = self._collect_tools()
        descriptions = [self._format_tool_for_llm(tool) for tool in tools]
        return "\n\n".join(descriptions)

    def get_driver_system_message(self, model_name: Optional[str] = None) -> str:
        """
        Formulates the system prompt to instruct the LLM on tool usage.

        Parameters
        ----------
        model_name : Optional[str]
            An optional name of the target LLM.

        Returns
        -------
        str
            The complete system message to be prepended to the conversation context
            for the LLM.
        """
        logger.info("Generating system message for the LLM.")
        system_message = (
            "You are a helpful assistant with access to these tools:\n\n"
            f"{self.get_function_description(model_name)}\n"
            "Choose the appropriate tool based on the user's question. "
            "If no tool is needed, reply directly.\n\n"
            "IMPORTANT: When you need to use a tool, you must ONLY respond with "
            "the exact JSON object format below, nothing else:\n"
            "{\n"
            '    "tool": "tool-name",\n'
            '    "arguments": {\n'
            '        "argument-name": "value"\n'
            "    }\n"
            "}\n\n"
            "After receiving a tool's response:\n"
            "1. Transform the raw data into a natural, conversational response\n"
            "2. Keep responses concise but informative\n"
            "3. Focus on the most relevant information\n"
            "4. Use appropriate context from the user's question\n"
            "5. Avoid simply repeating the raw data\n\n"
            "Please use only the tools that are explicitly defined above."
        )
        logger.debug(f"System message generated for the LLM: \n{system_message}\n")
        return system_message

    @staticmethod
    def _extract_json(raw: str) -> str | None:
        """Return first JSON object in `raw`, stripping markdown fences."""
        try:
            if raw.strip().startswith("```"):
                raw = re.sub(r"^```[^\n]*\n", "", raw.strip())
                raw = re.sub(r"\n```$", "", raw)
            match = re.search(r"\{.*\}", raw, re.S)
            return match.group(0) if match else None
        except Exception as e:
            logging.error(f"Error extracting JSON: {e}")
            return None

    def process_llm_response(self, llm_response: str | dict, *, streaming: bool = False) -> DriverResponse:
        """Parse the LLM's response, identify tool calls, and dispatch for execution.

        Parameters
        ----------
        llm_response :
            The raw string content from the LLM's assistant message, or a
            structured native tool-call object.
        streaming :
            Whether the driver is processing incremental streaming chunks.

        Returns
        -------
        DriverResponse
            Self-contained result with status flags and pre-formatted messages.
        """
        logger.info("Processing LLM response")
        logger.debug(f"{llm_response}")

        llm_text = llm_response if isinstance(llm_response, str) else json.dumps(llm_response)

        json_block = self._extract_json(llm_text)
        if not json_block:
            return DriverResponse()

        try:
            parsed = json.loads(json_block)
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing LLM response as JSON: {e}")
            return DriverResponse(
                call_failed=True,
                call_detail=f"JSON parse error: {e}",
                messages=[
                    {"role": "assistant", "content": llm_text},
                ],
            )

        tool_name = parsed.get("tool")
        arguments = parsed.get("arguments", {})

        if not tool_name:
            return DriverResponse(
                call_failed=True,
                call_detail="Tool call detected but no 'tool' field found.",
                retry_prompt="Return exactly one JSON object with fields: tool and arguments.",
                messages=[
                    {"role": "assistant", "content": llm_text},
                    {"role": "system", "content": "Return exactly one JSON object with fields: tool and arguments."},
                ],
            )

        logger.info(f"Attempting to execute tool '{tool_name}' with arguments: {arguments}")

        for driver in self.drivers:
            if any(tool.name == tool_name for tool in driver.list_tools()):
                logger.info(f"Dispatching tool '{tool_name}' to driver '{driver.meta.name}'.")
                try:
                    result = driver.execute_tool(tool_name, arguments)
                    logger.info(f"Tool '{tool_name}' executed successfully.")
                    return DriverResponse(
                        tool_call_result=result,
                        call_executed=True,
                        messages=[
                            {"role": "assistant", "content": llm_text},
                            {"role": "system", "content": str(result)},
                        ],
                    )
                except Exception as e:
                    logger.error(f"Tool '{tool_name}' execution failed: {e}", exc_info=True)
                    retry = f"Tool '{tool_name}' execution failed: {e}. Check argument names and value types, then retry."
                    return DriverResponse(
                        call_failed=True,
                        call_detail=f"Tool '{tool_name}' execution failed: {e}",
                        retry_prompt=retry,
                        messages=[
                            {"role": "assistant", "content": llm_text},
                            {"role": "system", "content": retry},
                        ],
                    )

        logger.warning(f"No matching tool '{tool_name}' found across all drivers.")
        retry = f"No matching tool '{tool_name}' found. Available tools: {', '.join(t.name for t in self._collect_tools())}."
        return DriverResponse(
            call_failed=True,
            call_detail=f"No matching tool '{tool_name}' found across registered drivers.",
            retry_prompt=retry,
            messages=[
                {"role": "assistant", "content": llm_text},
                {"role": "system", "content": retry},
            ],
        )

    @staticmethod
    def _format_tool_for_llm(tool: Tool) -> str:
        """Formats a single `Tool` object into a human-readable string for the LLM."""
        args_desc = []
        for param in tool.parameters:
            desc = f"- {param.name}: {param.description}"
            if param.required:
                desc += " (required)"
            args_desc.append(desc)

        return f"""Tool: {tool.name}
Description: {tool.description}
Arguments:
{chr(10).join(args_desc)}"""
