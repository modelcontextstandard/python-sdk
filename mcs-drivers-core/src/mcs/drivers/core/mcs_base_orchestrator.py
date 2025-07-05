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

from . import MCSDriver, MCSToolDriver, Tool, DriverMeta, DriverBinding

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
        # The meta attribute combines bindings from all aggregated drivers.
        # It sets default values for id, name, version, supported_llms, and capabilities.
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

        This description is typically formatted as a string suitable for inclusion
        in a system prompt, allowing the LLM to understand the available tools,
        their purposes, and their required parameters.

        Parameters
        ----------
        model_name : Optional[str]
            An optional name of the target LLM. While this orchestrator generates
            a generic description, future implementations could use this to tailor
            the output for specific LLMs (e.g., format variations).

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

        This prompt explains the role of the assistant, presents the available tools,
        and defines the strict JSON format the LLM must use when making a tool call.
        It also provides guidance for transforming raw tool output into conversational responses.

        Parameters
        ----------
        model_name : Optional[str]
            An optional name of the target LLM. This can be used for future
            model-specific prompt adjustments (e.g., varying tone or specific instructions).

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


    def process_llm_response(self, llm_response: str) -> Any:
        """
        Parses the LLM's response, identifies tool calls, and dispatches them for execution.

        This method expects the LLM's response to be a JSON string formatted as
        a tool call (as specified in `get_driver_system_message`). It then iterates
        through registered drivers to find the tool and executes it using `execute_tool`.

        Parameters
        ----------
        llm_response : str
            The raw string content from the LLM's assistant message, expected to be
            a JSON string representing a tool call.

        Returns
        -------
        Any
            The raw result returned by the `execute_tool` method of the relevant driver.
            If the `llm_response` is not a tool call or no matching tool is found,
            it may raise an error or return the original `llm_response` (depending on error handling).

        Raises
        ------
        RuntimeError
            If there's an error parsing the LLM's response or if no matching tool is found
            among the aggregated drivers.
        """
        logger.info(f"Processing LLM response")
        logger.debug(f"{llm_response}")

        json_block = self._extract_json(llm_response)
        if not json_block:
            return llm_response  # treat as plain text

        try:
            parsed = json.loads(llm_response)
            tool_name = parsed.get("tool")
            arguments = parsed.get("arguments", {})

            if not tool_name:
                logger.error("LLM response is missing the 'tool' key.")
                raise ValueError("LLM response JSON is missing the 'tool' key.")

            logger.info(f"Attempting to execute tool '{tool_name}' with arguments: {arguments}")

            for driver in self.drivers:
                # Prüfe, ob das Tool in diesem Treiber vorhanden ist
                if any(tool.name == tool_name for tool in driver.list_tools()):
                    logger.info(f"Dispatching tool '{tool_name}' to driver '{driver.meta.name}'.")
                    result = driver.execute_tool(tool_name, arguments)
                    logger.info(f"Tool '{tool_name}' executed successfully.")
                    logger.debug(f"Raw result from tool '{tool_name}': {result}")
                    return result

            logger.warning(f"No matching tool '{tool_name}' found across all drivers.")
            raise ValueError(f"No matching tool '{tool_name}' found")

        except json.JSONDecodeError as e:
            logger.error(f"Error parsing LLM response as JSON: {e}")
            raise RuntimeError(f"Error in Orchestrator: Failed to decode LLM response. Original error: {str(e)}")

        except Exception as e:
            logger.error(f"An unexpected error occurred in the orchestrator: {e}", exc_info=True)
            raise RuntimeError(f"Error in Orchestrator: {str(e)}")

    @staticmethod
    def _format_tool_for_llm(tool: Tool) -> str:
        """
        Formats a single `Tool` object into a human-readable string for the LLM.

        Parameters
        ----------
        tool : Tool
            The tool object to format.

        Returns
        -------
        str
            A string representation of the tool, including its name, description,
            and arguments with their descriptions and required status.
        """
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
