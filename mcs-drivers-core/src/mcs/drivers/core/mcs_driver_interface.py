"""MCS core driver interface.

Based on MCS Driver Contract v0.4

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
from typing import Any, Optional


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


@dataclass
class DriverResponse:
    """Self-contained result of a single ``process_llm_response`` call.

    Every call to ``process_llm_response`` returns a ``DriverResponse``
    that carries both the result and status information.  This keeps the
    driver itself stateless and thread-safe.

    Attributes
    ----------
    result :
        Raw output of the executed operation, or the unchanged LLM
        response when no call was detected / execution failed.
    call_executed :
        ``True`` when a tool call was found and successfully executed.
    call_failed :
        ``True`` when a tool-call signature was found but could not be
        parsed or executed.
    call_detail :
        Optional human-readable string explaining why the call failed
        (for debugging / logging).
    retry_prompt :
        Driver-authored prompt hint that the client can append to the
        conversation so the LLM can correct its output and retry.
    """
    result: Any
    call_executed: bool = False
    call_failed: bool = False
    call_detail: Optional[str] = None
    retry_prompt: Optional[str] = None

    @staticmethod
    def executed(result: Any) -> DriverResponse:
        """Convenience factory for a successful execution."""
        return DriverResponse(result=result, call_executed=True)

    @staticmethod
    def failed(
        llm_response: Any,
        detail: str | None = None,
        retry_prompt: str | None = None,
    ) -> DriverResponse:
        """Convenience factory for a detected-but-failed call."""
        return DriverResponse(
            result=llm_response,
            call_failed=True,
            call_detail=detail,
            retry_prompt=retry_prompt or (
                "Your previous response looked like a tool call but could "
                "not be parsed. Please try again using the exact format "
                "described in the system instructions."
            ),
        )

    @staticmethod
    def no_match(llm_response: Any) -> DriverResponse:
        """Convenience factory when no tool call was detected."""
        return DriverResponse(result=llm_response)


class MCSDriver(ABC):
    """Abstract base class for all MCS drivers.

    A driver is responsible for two core tasks:

    1.  Provide a **llm-readable function description** so an LLM can
        discover the available tools.
    2.  **Execute** the structured call emitted by the LLM and return the
        result inside a :class:`DriverResponse`.

    The combination of these two tasks allows any language model that
    supports function-calling to interact with the underlying system
    without knowing implementation details or transport specifics.

    The driver is **stateless** -- all per-call outcome information is
    returned inside the :class:`DriverResponse` object.  Conversation
    history is the client's responsibility.

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
    def process_llm_response(self, llm_response: str) -> DriverResponse:  # noqa: D401
        """Execute the structured call emitted by the LLM.

        Returns a :class:`DriverResponse` that carries the result and
        status flags:

        * **Executed** -- ``DriverResponse.executed(result)``
        * **Failed** -- ``DriverResponse.failed(llm_response, detail, retry_prompt)``
        * **No match** -- ``DriverResponse.no_match(llm_response)``

        Before signalling *detected but failed* the driver should attempt
        any configured self-healing patterns (e.g. fixing known
        model-specific formatting errors).

        When no call is detected the driver must return the input
        unchanged (via ``DriverResponse.no_match``) so that chaining
        across multiple drivers works correctly.

        Parameters
        ----------
        llm_response :
            The content of the assistant message.  Typically a JSON string
            that contains the selected ``tool`` (or function name) and its
            ``arguments``.

        Returns
        -------
        DriverResponse
            Self-contained result with status flags, detail, and
            optional retry prompt.
        """
