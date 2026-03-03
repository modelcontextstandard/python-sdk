"""MCS Tool Driver Interface.

Based on an extended MCS Driver Contract, this interface focuses on structured tool interaction.

A tool driver encapsulates two primary responsibilities:
1. **list_tools** – provide a list of available tools elements and their parameters.
2. **execute_tool** – execute a specified tool with provided arguments and return the raw result.

Implementations can use any underlying transport (e.g., HTTP, CAN-Bus, AS2, gRPC) and
manage any internal specification format (e.g., OpenAPI, JSON-Schema, proprietary JSON).

"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Optional

from . import DriverMeta


@dataclass
class ToolParameter:
    """Describes a single parameter for a Tool.

    Attributes
    ----------
    name : str
        The name of the parameter.
    description : str
        A brief description of what the parameter represents or its purpose.
    required : bool, optional
        Indicates whether the parameter is mandatory. Defaults to False.
    schema : Optional[dict[str, Any]], optional
        A dictionary representing the JSON schema for this parameter's type.
        For example: `{"type": "string", "enum": ["option1", "option2"]}`
        or `{"type": "integer", "format": "int32"}`.
    """
    name: str
    description: str
    required: bool = False
    schema: Optional[dict[str, Any]] = None


@dataclass
class Tool:
    """Describes a single callable tool provided by the driver.

    This structure aims to be a machine-readable definition of a function
    that an external entity (e.g., an orchestrator or an LLM capable of
    tool-calling) can understand and invoke.

    The three-tier identification mirrors both MCP and OpenAPI conventions:

    * ``name``  -- machine identifier (MCP ``name``, OpenAPI ``operationId``)
    * ``title`` -- short human-readable label (MCP ``title``, OpenAPI ``summary``)
    * ``description`` -- full text forwarded to the LLM, may contain multi-line
      prompt-engineering instructions (MCP ``description``, OpenAPI ``description``)

    A client or orchestrator can choose to expose only ``name`` + ``title``
    to the LLM to save context-window tokens and load the full
    ``description`` on demand when a tool is actually selected.

    At least one of ``title`` or ``description`` must be provided.
    When only ``title`` is given, ``description`` is auto-filled from it
    so that downstream consumers (e.g. ``PromptStrategy.format_tools``)
    always find a non-empty ``description``.

    Attributes
    ----------
    name : str
        Unique machine-readable identifier for the tool.
    title : str or None
        Optional short human-readable label for display and token-efficient
        tool listings.  Maps to OpenAPI ``summary`` / MCP ``title``.
    description : str or None
        Detailed description forwarded to the LLM.  May include usage
        instructions, constraints and examples.  Auto-filled from
        ``title`` when not provided explicitly.
    parameters : list[ToolParameter]
        Inputs required by the tool.
    """
    name: str
    title: Optional[str] = None
    description: Optional[str] = None
    parameters: list[ToolParameter] = None  # type: ignore[assignment]    

    def __post_init__(self) -> None:
        if self.parameters is None:
            self.parameters = []
        if not self.description and self.title:
            self.description = self.title
        if not self.description and not self.title:
            raise ValueError(
                f"Tool '{self.name}': at least one of 'title' or 'description' must be provided."
            )


class MCSToolDriver(ABC):
    """
    Interface for drivers that integrate with an orchestrator or driver by providing
    structured Tool objects instead of prompts and free-text communication.

    This interface decouples the LLM-specific prompting and response parsing
    from the driver's core responsibility, focusing solely on machine-readable
    tool definitions and their execution.

    Attributes
    ----------
    meta : DriverMeta
        Metadata about the driver, including its capabilities, bindings,
        and supported models. This allows an orchestrator to understand
        how to interact with and utilize the driver.
    """
    meta: DriverMeta

    @abstractmethod
    def list_tools(self) -> list[Tool]:
        """
        Returns a list of all tools provided by the driver.

        These tools should be described in a machine-readable format
        (using the `Tool` and `Parameter` dataclasses), allowing an
        orchestrator or LLM to understand their capabilities and required inputs.

        Returns
        -------
        List[Tool]
            A list of `Tool` objects, each describing an available function.
        """
        pass  # pragma: no cover

    @abstractmethod
    def execute_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        """
        Executes the specified tool with the given arguments and returns its result.

        This method is responsible for:
        1. Validating the `tool_name` and `arguments` against the tool's definition.
        2. Routing the call to the underlying system or service.
        3. Collecting the result from the tool's execution.

        Parameters
        ----------
        tool_name : str
            The name of the tool to execute, as returned by `list_tools`.
        arguments : dict[str, Any]
            A dictionary containing the arguments for the tool, where keys are
            parameter names and values are their corresponding inputs.

        Returns
        -------
        Any
            The raw output of the executed tool. The orchestrator or client
            is responsible for interpreting and processing this result.
        """
        pass  # pragma: no cover
