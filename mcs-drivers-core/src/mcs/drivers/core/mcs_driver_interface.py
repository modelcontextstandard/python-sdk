"""MCS core driver interface.

Based on MCS driver Contract v0.1

A driver encapsulates two mandatory responsibilities:
1. **get_function_description** – fetch a machine‑readable function spec
2. **process_llm_response** – execute a structured call emitted by the LLM

Implementations can use any transport (HTTP, CAN‑Bus, AS2, …) and any
specification format (OpenAPI, JSON‑Schema, proprietary JSON). The interface
keeps the integration surface minimal and self‑contained.

"""

from __future__ import annotations

from dataclasses import dataclass
from abc import ABC, abstractmethod
from typing import Any


@dataclass(frozen=True)
class DriverBinding:
    """Describes a single supported interface binding.

    A binding links a high-level protocol, its transport mechanism,
    and the format used to describe its callable functions.

    Attributes
    ----------
    protocol :
        Logical protocol layer, e.g. "REST", "GraphQL", "EDI"
    transport :
        Transport channel, e.g. "HTTP", "MQTT", "AS2"
    spec_format :
        Description format, e.g. "OpenAPI", "JSON-Schema", "WSDL", "Custom"

    Example
    -------
    >>> DriverBinding(protocol="REST", transport="HTTP", spec_format="OpenAPI")
    """
    protocol: str
    transport: str
    spec_format: str


@dataclass(frozen=True)
class DriverMeta:
    """Static metadata that describes the capabilities of a driver.

    The metadata can be inspected by orchestrators or clients to determine
    compatibility, supported models, and runtime features.

    Attributes
    ----------
    id :
        Globally unique identifier (e.g. UUID)
    name :
        Human-readable name of the driver
    version :
        Semantic version string (e.g. "1.0.0")
    bindings :
        One or more supported interface definitions.
    supported_llms :
        Tuple of supported model identifiers. Use "*" to match all models. None if the driver is a MCS Tool Driver.
    capabilities :
        Optional list of runtime features like "healthcheck", "streaming", etc.

    Example
    -------
    >>> DriverMeta(
    ...     id="c0c24b2f-0d18-425b-8135-2155e0289e00",
    ...     name="HTTP REST Driver",
    ...     version="1.0.0",
    ...     bindings=(
    ...         DriverBinding(protocol="REST", transport="HTTP", spec_format="OpenAPI"),
    ...     ),
    ...     supported_llms=("*", "claude-3"),
    ...     capabilities=("healthcheck",)
    ... )
    """
    id: str
    name: str
    version: str
    bindings: tuple[DriverBinding, ...]
    supported_llms: tuple[str, ...] | None
    capabilities: tuple[str, ...]


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

        It is important to return the raw llm_response exactly as it was, when
        not executing was made, so that a client can determine whether the
        response was processed by the driver or not. This is necessary if
        multiple drivers were chained together.

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
