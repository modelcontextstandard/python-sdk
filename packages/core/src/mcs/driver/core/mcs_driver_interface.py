"""MCS core driver interface.

Based on MCS Driver Contract v0.6

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

from dataclasses import dataclass, field, replace
from abc import ABC, abstractmethod
from typing import Any


@dataclass(frozen=True)
class DriverBinding:
    """Describes what a driver does and how it reaches its backend.

    Attributes
    ----------
    capability :
        The driver's **subject matter** -- what it provides, e.g. "csv", "rest",
        "filesystem", "pdf". This is the primary selector: *"give me a driver for
        `mail` over `imap`."* Despite the similar name it is unrelated to
        :attr:`DriverMeta.capabilities`, which lists the optional *contracts* a
        driver satisfies.
    adapter :
        Which backend implementation is used, e.g. "localfs", "http", "smb", "s3".
        Use ``"*"`` when the driver works with any adapter.
    spec_format :
        Description format used for the tool definitions,
        e.g. "OpenAPI", "JSON-Schema", "Custom".

    Example
    -------
    >>> DriverBinding(capability="rest", adapter="http", spec_format="OpenAPI")
    >>> DriverBinding(capability="csv", adapter="localfs", spec_format="Custom")
    """
    capability: str
    adapter: str
    spec_format: str


@dataclass(frozen=True)
class DriverMeta:
    """The **data sheet** of a driver -- what it does and what it supports.

    A plain, serializable record that can be read *before or without* holding
    the driver object: from a registry entry, a package index, a JSON file. That
    is what it is for -- **finding** the right driver among many.

    Asking a driver you already hold what it can *do* is a different question
    with a different answer: ``isinstance(driver, SupportsX)``, straight from
    the object. Since ADR-0002 nothing wraps a driver any more, so that answer is
    always available and always current -- see :attr:`capabilities`.

    Attributes
    ----------
    id :
        Globally unique identifier (e.g. UUID).
    name :
        Human-readable name of the driver.
    version :
        Semantic version string (e.g. "1.0.0").
    bindings :
        One or more subject-matter + adapter combinations the driver supports.
        Selection by *what a driver is for* starts here (see
        :class:`DriverBinding`).
    supported_llms :
        Tuple of supported model identifiers. Use ``"*"`` to match all
        models. ``None`` if the driver is a pure MCS ToolDriver.
    capabilities :
        The optional contracts the driver **class** satisfies, as their
        ``CAPABILITY`` flags: the roles it can play (``"standalone"``,
        ``"orchestratable"``) and the optional features it implements
        (``"healthcheck"``, ``"streaming"``, ``"native_tools"``).

        This is a **projection** of those contracts, produced by
        :meth:`derive_capabilities` -- not a second source of truth kept in sync
        by hand. It exists for the consumer who holds *metadata but no driver*;
        a consumer holding the driver asks the object with ``isinstance``.

        Strictly static, and deliberately so: it describes the class, not an
        instance. What a particular instance was configured with at runtime --
        which middleware the client hung into it -- is not a property of the
        driver and stays out of here.

    Example
    -------
    >>> DriverMeta(
    ...     id="c0c24b2f-0d18-425b-8135-2155e0289e00",
    ...     name="REST HTTP Driver",
    ...     version="1.0.0",
    ...     bindings=(
    ...         DriverBinding(capability="rest", adapter="http", spec_format="OpenAPI"),
    ...     ),
    ...     supported_llms=("*",),
    ...     capabilities=("healthcheck",)
    ... )
    """
    id: str
    name: str
    version: str
    bindings: tuple[DriverBinding, ...]
    supported_llms: tuple[str, ...] | None
    capabilities: tuple[str, ...]

    # Two operations on the data sheet: one writes it (the projection), one reads
    # it (the catalog lookup). Neither is the runtime check -- for that, ask the
    # object: ``isinstance(driver, Contract)``.

    def has_capability(self, contract: type) -> bool:
        """Return ``True`` if *contract*'s ``CAPABILITY`` flag is on the data sheet.

        The **catalog** read, for a consumer that has metadata but no driver
        object -- a registry, a package index, a config file. It keeps the flag
        together with its contract instead of forcing string literals on the
        caller.

        This is deliberately *not* the runtime check. When you hold the driver,
        ``isinstance(driver, Contract)`` is the direct answer, cannot go stale,
        and is the route a client should take.
        """
        return getattr(contract, "CAPABILITY", None) in self.capabilities

    def derive_capabilities(self, cls: type) -> "DriverMeta":
        """Return a copy with every capability flag *cls* carries added (idempotent).

        The **projection** that keeps the data sheet honest. Scans *cls*'s MRO
        for ``CAPABILITY`` attributes -- the flag each contract declares
        (``"standalone"`` on :class:`MCSDriver`, ``"orchestratable"`` on
        :class:`MCSToolDriver`, ``"native_tools"`` on ``SupportsNativeTools``, …)
        -- and **unions** them with whatever this metadata already declares. Pass
        a single contract to add exactly that flag, or the driver class to fold
        in everything it implements.

        Because the flags are *derived from* the contracts rather than typed out
        beside them, the metadata cannot drift away from the object: it is a
        serializable shadow of the truth, not a second copy of it. A driver may
        still list flags explicitly (readable, inspectable by human and machine)
        -- the union is the same complete tuple either way. Bases without a flag
        are skipped.

        Feed it *classes*, never instance state: the result must stay
        reproducible from the class alone, or the data sheet stops being static.
        """
        flags = list(self.capabilities)
        for base in cls.__mro__:
            flag = base.__dict__.get("CAPABILITY")
            if isinstance(flag, str) and flag not in flags:
                flags.append(flag)
        return replace(self, capabilities=tuple(flags))


@dataclass
class ToolCallRecord:
    """What the driver did for one tool call -- for client observability / UX.

    The client *displays* this (which tool ran, with what arguments, what came
    back); control flow stays on the :class:`DriverResponse` status flags. One
    record is produced for **every** call the driver processed this response --
    ``result`` on success, ``error`` on failure. This keeps the two concerns
    separate: ``messages`` is for the LLM (native history, opaque), while
    ``executed_calls`` is the readable, per-call report for the client.
    """
    name: str
    arguments: dict[str, Any]
    result: Any = None
    error: str | None = None
    tool_call_id: str | None = None


@dataclass
class DriverResponse:
    """Self-contained result of a single ``process_llm_response`` call.

    Every call to ``process_llm_response`` returns a ``DriverResponse``
    that carries both the result and status information.  This keeps the
    driver itself stateless and thread-safe.

    Attributes
    ----------
    executed_calls :
        Per-call report (:class:`ToolCallRecord` list) for client observability
        -- which tools ran, with what arguments, what came back (result or error).
        This is the readable surface for UX; the client displays it and never
        drives control flow from it. One record per call the driver processed
        (a batch may hold several parallel calls).
    call_executed :
        ``True`` once the driver executed the call(s) -- regardless of how many,
        and regardless of whether some of them failed.
    call_failed :
        ``True`` when **any** processed call failed (unknown tool, bad arguments,
        execution error). May be ``True`` **together with** ``call_executed`` for a
        partially-successful batch; the per-call detail is in ``executed_calls``.
    call_pending :
        ``True`` while a call is still forming in the stream (the batch is not yet
        complete). The client keeps feeding chunks; nothing was executed.
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

    Streaming display is *not* on this object -- it is the buffer's concern:
    after ``process_llm_response(buf)`` the client reads ``buf.text()``. The
    driver only manipulates the buffer (holds a forming call) and reports status
    here; display stays with the buffer, keeping the two concerns separate.
    """
    call_executed: bool = False
    call_failed: bool = False
    call_pending: bool = False
    retry_prompt: str | None = None
    messages: list[dict[str, Any]] | None = field(default=None)
    executed_calls: list[ToolCallRecord] | None = field(default=None)


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
        :class:`DriverMeta` instance that declares capability, adapter,
        spec format and supported models.  It acts like a device-ID so an
        orchestrator can pick the right driver at runtime.

    A driver that implements this interface is usable **standalone** (directly
    with an LLM), advertised via the ``"standalone"`` capability flag.
    """
    CAPABILITY = "standalone"
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
    def process_llm_response(self, llm_response: str | dict) -> DriverResponse:  # noqa: D401
        """Parse the LLM output for a structured call. If found, execute it.

        The returned :class:`DriverResponse` tells the client what happened:

        * ``response.call_executed`` -- a tool call was found and
          executed.  ``response.executed_calls`` reports each call
          (name, arguments, result or error) for the client to display.
          ``response.messages`` contains pre-formatted conversation
          entries the client can append directly to its message history.
        * ``response.call_failed`` -- a tool-call signature was found
          but could not be parsed or executed.  The reason is on the
          matching :class:`ToolCallRecord`'s ``error``.
          ``response.retry_prompt`` contains a driver-authored hint
          the client can append to the conversation for a retry, and
          ``response.messages`` the entries needed for that round
          (assistant message + retry hint).
        * Neither flag set -- no tool call was detected.
          The LLM output is a final answer for the user.
          ``response.messages`` is ``None``; the client handles the
          final answer directly.

        Before signalling *failed* the driver should attempt any
        configured self-healing patterns (e.g. fixing known
        model-specific formatting errors) -- see Section 10 in docs.

        Parameters
        ----------
        llm_response :
            The raw content of the assistant message (``str``) or a
            structured native tool-call object (``dict``) for LLMs
            that emit tool calls as structured data rather than text.

        For chunk-by-chunk streaming, use the ``SupportsStreaming``
        capability: it *widens* this input to also accept an
        ``LLMStreamBuffer`` (plus a ``new_stream_buffer`` factory), and the
        type is the signal -- given a buffer the driver reports
        ``call_pending`` while a call is still forming.  The base contract
        itself stays streaming-agnostic.

        Returns
        -------
        DriverResponse
            Self-contained result object with ``call_executed``,
            ``call_failed``, ``call_pending``, ``executed_calls``,
            ``retry_prompt``, and ``messages``.
        """
