"""MCS Tool Driver Interface.

Based on an extended MCS Driver Contract, this interface focuses on structured tool interaction.

A tool driver encapsulates two primary responsibilities:
1. **list_tools** – provide a machine-readable list of available tools and their parameters.
2. **execute_tool** – execute a specified tool with provided arguments and return the raw result.

Implementations can use any underlying transport (e.g., HTTP, CAN-Bus, AS2, gRPC) and
manage any internal specification format (e.g., OpenAPI, JSON-Schema, proprietary JSON).
This interface aims to keep the integration surface minimal, explicit, and self-contained,
enabling direct tool-centric communication.

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

    Attributes
    ----------
    name : str
        The unique name of the tool, used to identify it.
    description : str
         A detailed description of what the tool does and when it should be used.
    parameters : list[ToolParameter]
        A list of `Parameter` objects, defining the inputs required by the tool.
    """
    name: str
    description: str
    parameters: list[ToolParameter]


class MCSToolDriver(ABC):
    """
    Interface for drivers that integrate with an orchestrator by providing
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
