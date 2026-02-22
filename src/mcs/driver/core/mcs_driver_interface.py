"""MCS core driver interface.

Based on MCS Driver Contract v0.5

A driver encapsulates three responsibilities:
1. **get_function_description** – provide a function spec
   (may be model-specific, e.g. XML for Grok, JSON for GPT or raw pass-through, e.g. OpenAPI, ...)
2. **get_driver_system_message** – provide a ready-to-use system prompt
   (typically wraps get_function_description with prompt guidance)
3. **process_llm_response** – processes the LLM output (text or native tool-call object),
   searches for a structured call, executes it if found, and returns a DriverResponse
   that includes pre-formatted messages for the client's conversation history.

Implementations can use any transport (HTTP, CAN‑Bus, AS2, …) and any
specification format (OpenAPI, JSON‑Schema, proprietary JSON). The interface
keeps the integration surface minimal and self‑contained.

"""

from __future__ import annotations

from dataclasses import dataclass, field
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
    ...     supported_llms=("*", "claude-4"),
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
    tool_call_result :
        Raw output of the executed tool operation.  Only meaningful when
        ``call_executed`` is ``True``.  ``None`` when no call was detected
        or when the call failed.
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
    messages :
        Pre-formatted conversation messages that the client can append
        directly to its message history.  The driver is responsible for
        building these in the correct format (e.g. assistant message
        with the original LLM output, followed by a tool-result message).
        ``None`` when no messages need to be appended (e.g. final answer
        with no tool call detected).
    """
    tool_call_result: Any = None
    call_executed: bool = False
    call_failed: bool = False
    call_detail: str | None = None
    retry_prompt: str | None = None
    messages: list[dict[str, Any]] | None = field(default=None)


class MCSDriver(ABC):
    """Abstract base class for all MCS drivers.

    A driver is responsible for two core tasks:

    1.  Provide a **function description** so an LLM can
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
        """Return the raw or driver transformed function specification.

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

        The default implementation *should* call `get_function_description`
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
    def process_llm_response(self, llm_response: str | dict, *, streaming: bool = False) -> DriverResponse:  # noqa: D401
        """Parse the LLM output for a structured call. If found, execute it.

        The returned :class:`DriverResponse` tells the client what happened:

        * ``response.call_executed`` -- a tool call was found and
          successfully executed.  ``response.tool_call_result`` contains
          the raw tool output.  ``response.messages`` contains
          pre-formatted conversation entries the client can append
          directly to its message history.
        * ``response.call_failed`` -- a tool-call signature was found
          but could not be parsed or executed.
          ``response.retry_prompt`` contains a driver-authored hint
          the client can append to the conversation for a retry.
          ``response.call_detail`` may carry debugging information.
          ``response.messages`` contains the entries needed for a
          retry round (assistant message + retry hint).
        * Neither flag set -- no tool call was detected.
          The LLM output is a final answer for the user.
          ``response.messages`` is ``None``; the client handles the
          final answer directly.

        Before signalling *failed* the driver should attempt any
        configured self-healing patterns (e.g. fixing known
        model-specific formatting errors) -- see Section 9 in docs.

        Parameters
        ----------
        llm_response :
            The raw content of the assistant message (``str``) or a
            structured native tool-call object (``dict``) for LLMs
            that emit tool calls as structured data rather than text.
        streaming :
            When ``True``, the driver knows it is receiving incremental
            chunks.  It may skip expensive operations like self-healing
            on intermediate chunks and only apply them on the final call.

        Returns
        -------
        DriverResponse
            Self-contained result object with ``tool_call_result``,
            ``call_executed``, ``call_failed``, ``call_detail``,
            ``retry_prompt``, and ``messages``.
        """
