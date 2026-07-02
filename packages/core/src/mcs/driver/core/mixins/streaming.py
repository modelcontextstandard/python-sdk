"""Optional contract for drivers that process streaming tool-call responses.

When an LLM streams its response chunk by chunk, the client reassembles it with an
:class:`~mcs.driver.core.LLMStreamBuffer` -- created **directly**, because the
buffer is MCS (SDK-agnostic) and not bound to any driver -- and hands
``buf.as_dict()`` to this driver's streaming-aware ``process_llm_response``:

    buf = LLMStreamBuffer()
    for chunk in stream:
        text = buf.add(chunk)                          # feed raw chunk; get content delta
        dr = streamer.process_llm_response(buf.as_dict(), streaming=True)
        if dr.call_executed or dr.call_failed:
            buf.reset()                                # done with this call; find the next
        elif dr.call_pending:                          # a tool call is building up
            ...
        elif text:
            print(text, end="")                        # content token

This capability marks a driver whose ``process_llm_response`` understands the
``streaming`` flag -- reporting ``call_pending`` while a call is still incomplete
instead of failing. A plain ``MCSDriver`` never has to stream. The client detects
support via ``driver.meta.has_capability`` / ``DriverMeta.resolve_capability`` and
depends on this capability, not on any concrete driver class.

The buffer is deliberately *not* a driver method: its reassembly is determined by
the client's LLM/SDK (constant per turn) and identical for every driver, and
drivers compose (a chain has no single one to own it). See
``packages/core/docs/streaming-tool-formats.md``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..mcs_driver_interface import DriverResponse


class SupportsStreaming(ABC):
    """Opt-in contract: a streaming-aware ``process_llm_response``."""

    #: Capability flag advertised in ``DriverMeta.capabilities`` when a driver
    #: satisfies this contract.
    CAPABILITY = "streaming"

    @abstractmethod
    def process_llm_response(
        self, llm_response: str | dict, *, streaming: bool = False,
    ) -> "DriverResponse":
        """Process the LLM output, streaming-aware.

        Extends :meth:`~mcs.driver.core.MCSDriver.process_llm_response` with the
        ``streaming`` flag: when ``True``, an incomplete tool call is reported as
        ``call_pending`` (the client keeps feeding chunks) instead of failing.
        This is why streaming lives here, not on the base contract -- the client
        calls it on the resolved ``SupportsStreaming`` layer, so a plain
        ``MCSDriver`` can never be asked to stream.
        """
        ...
