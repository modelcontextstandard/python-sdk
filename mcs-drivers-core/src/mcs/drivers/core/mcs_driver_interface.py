from __future__ import annotations

"""MCS core driver interface.

Based on MCS driver Contract v0.1

A driver encapsulates two mandatory responsibilities:
1. **get_function_description** – fetch a machine‑readable function spec
2. **process_llm_response** – execute a structured call emitted by the LLM

Implementations can use any transport (HTTP, CAN‑Bus, AS2, …) and any
specification format (OpenAPI, JSON‑Schema, proprietary JSON). The interface
keeps the integration surface minimal and self‑contained.

"""

from dataclasses import dataclass
from abc import ABC, abstractmethod
from typing import Any


@dataclass(frozen=True)
class DriverMeta:
    """Static metadata that classifies a driver.

        The fields allow an orchestrator (or any other component) to decide
        whether a given driver is suitable for a particular function-calling
        scenario.

        Attributes
        ----------
        protocol :
            High-level protocol the driver speaks on the *logical* layer,
            e.g. ``"REST"``, ``"EDI"``, ``"GraphQL"``.
        transport :
            Physical or network transport used to reach the target system,
            e.g. ``"HTTP"``, ``"AS2"``, ``"CAN"``, ``"MQTT"``.
        spec_format :
            Format of the machine-readable function description understood
            by this driver, e.g. ``"OpenAPI"``, ``"JSON-Schema"``,
            ``"WSDL"``, or ``"Custom"``.
        supported_models :
            Tuple of model identifiers that the driver’s prompt template is
            explicitly tuned for.  Use a wildcard like ``"*"``
            to indicate a generic prompt that should work for *any* LLM.

        Example
        -------
        >>> DriverMeta(
        ...     id="c0c24b2f-0d18-425b-8135-2155e0289e00"
        ...     name="HTTP REST Driver",
        ...     version="1.0.0",
        ...     protocol="REST",
        ...     transport="HTTP",
        ...     spec_format="OpenAPI",
        ...     target_llms=("*", "claude-3")
        ...     capabilities=("healthcheck"),
        ... )
        """
    id: str
    name: str
    version: str
    protocol: str
    transport: str
    spec_format: str  # e.g. "OpenAPI", "JSON-Schema", "Custom"
    target_llms: tuple[str]  # e.g. ["*", "claude-3"]
    capabilities: tuple[str]  # e.g. ["healthcheck", "status"]


class MCSDriver(ABC):
    """Abstract base class for all MCS drivers.

    A driver is responsible for two core tasks:

    1.  Provide a **llm-readable function description** so an LLM can discover the available tools.
    2.  **Execute** the structured call emitted by the LLM and return the
        raw result.

    The combination of these two tasks allows any language model that
    supports function-calling to interact with the underlying system
    without knowing implementation details or transport specifics.

    Attributes
    ----------
    meta :
        :class:`DriverMeta` instance that declares protocol, transport,
        spec format and supported models.  It acts like a device-ID so an
        orchestrator can pick the right driver at runtime.
    """
    meta: DriverMeta

    @abstractmethod
    def get_function_description(self, model_name: str | None = None) -> str:  # noqa: D401
        """Return the raw function specification.

        Parameters
        ----------
        model_name :
            Optional name of the target LLM.  Implementations may return a
            model-specific subset or representation if necessary.

        Returns
        -------
        str
            A llm-readable string (e.g. OpenAPI JSON, JSON-Schema,
            XML, plain english) that fully describes the callable functions.
        """

    @abstractmethod
    def get_driver_system_message(self, model_name: str | None = None) -> str:  # noqa: D401
        """Return the system prompt that exposes the tools to the LLM.

        The default implementation *may* call `get_function_description`
        and embed it in a prompt template, but drivers are free to provide
        their own model-specific wording.

        Parameters
        ----------
        model_name :
            Optional target LLM name to adjust the prompt (e.g. temperature
            hints, token limits, preferred JSON style, or using a complete different prompt).

        Returns
        -------
        str
            The full system prompt to be injected before the user message.
        """

    @abstractmethod
    def process_llm_response(self, llm_response: str) -> Any:  # noqa: D401
        """Execute the structured call emitted by the LLM.

        The driver must parse *llm_response*, route the call via its
        transport layer, collect the result, and return it in raw form
        (string, dict, binary blob – whatever is appropriate).

        Parameters
        ----------
        llm_response :
            The content of the assistant message.  Typically a JSON string
            that contains the selected ``tool`` (or function name) and its
            ``arguments``.

        Returns
        -------
        Any
            Raw output of the executed operation.  The conversation
            orchestrator is responsible for post-processing or converting
            it into a user-friendly reply.
        """
