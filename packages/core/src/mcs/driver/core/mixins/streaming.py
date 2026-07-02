"""Optional contract for drivers that process streaming tool-call responses.

When an LLM streams its response chunk by chunk, the client reassembles it with an
:class:`~mcs.driver.core.LLMStreamBuffer` -- created **directly**, because the
buffer is MCS (SDK-agnostic) and not bound to any driver -- and hands the **buffer
itself** to this driver's ``process_llm_response``:

    buf = LLMStreamBuffer()
    for chunk in stream:
        buf.add(chunk)
        dr = streamer.process_llm_response(buf)        # a buffer argument == streaming
        if (text := buf.text()):
            print(text, end="")                        # what the driver let through
        elif dr.call_pending:                          # a tool call is building up
            ...
        # on call_executed / call_failed the driver ran the tool and cleared the
        # buffer itself -- the client never touches the buffer's lifecycle

**No ``streaming`` flag** -- the *type* is the signal. ``MCSDriver.process_llm_response``
stays ``(str | dict)`` and is streaming-agnostic; this capability *widens* the input to
also accept an ``LLMStreamBuffer`` (Liskov-safe: contravariant input widening). Only a
stream-aware driver knows the buffer type, so a plain ``MCSDriver`` can never be asked to
stream. When given a buffer, the driver does its work **on the buffer** (holding a forming
call) and reports only *status* here -- display stays with the buffer (``buf.text()``),
keeping the two concerns separate. The client stays format-agnostic (identical loop for
native and text-embedded calls) and never inspects the chunk.

The client detects support via ``driver.meta.has_capability`` / ``DriverMeta.resolve_capability``
and depends on this capability, not on any concrete driver class. The buffer is
deliberately not a driver method (reassembly is an LLM/SDK concern, identical for every
driver, and drivers compose). See ``packages/core/docs/streaming-tool-formats.md``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..mcs_driver_interface import DriverResponse
    from ..llm_stream_buffer import LLMStreamBuffer


class SupportsStreaming(ABC):
    """Opt-in contract: a streaming-aware ``process_llm_response``."""

    #: Capability flag advertised in ``DriverMeta.capabilities`` when a driver
    #: satisfies this contract.
    CAPABILITY = "streaming"

    @abstractmethod
    def process_llm_response(
        self, llm_response: "str | dict | LLMStreamBuffer",
    ) -> "DriverResponse":
        """Process the LLM output; streaming when given an ``LLMStreamBuffer``.

        Widens :meth:`~mcs.driver.core.MCSDriver.process_llm_response` to also accept
        an :class:`~mcs.driver.core.LLMStreamBuffer`. A buffer argument means the driver
        is mid-stream: it reassembles/classifies the accumulated output, reports
        ``call_pending`` while a call is still forming (instead of failing), holds display
        of a forming call on the buffer (the client reads ``buf.text()``), and executes
        once the call is complete. A plain ``str | dict`` is handled as the base does.
        """
        ...
