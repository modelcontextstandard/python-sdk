"""Optional contract for drivers that can provide tools in a native API format.

The MCS core is text-centric: ``get_driver_system_message`` returns a string
with the tools embedded as text, which every model can consume. Some LLM APIs
(OpenAI, Anthropic, ...) instead accept the tools as a separate, structured
``tools`` parameter and return structured tool-calls.

``SupportsNativeTools`` bridges that gap: ``get_native_tool_context`` returns a
:class:`NativeToolContext` carrying the system message *and* -- when the target
model supports native tool-calling -- the tool definitions as native dicts.
When it does not, ``tools`` is ``None`` and the tools stay embedded in
``system_message`` (the plain-text path). It is therefore an *extension* of
``get_driver_system_message``, not a replacement.

This is a **pure contract** -- the example implementation lives in
``BaseDriver``. Clients detect support via ``driver.meta.has_capability`` and
resolve it via ``DriverMeta.resolve_capability(driver, SupportsNativeTools)``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass
class NativeToolContext:
    """Everything a client needs to initialise a native-tool LLM call.

    Attributes
    ----------
    system_message :
        The system prompt text. Always present.
    tools :
        Tool definitions in the LLM provider's native format (e.g. OpenAI's
        ``{"type": "function", "function": {...}}`` schema), or ``None`` when
        the tools are already encoded inside ``system_message`` (text path).
    """
    system_message: str
    tools: list[dict[str, Any]] | None = None


class SupportsNativeTools(ABC):
    """Opt-in contract: expose tools in the LLM provider's native format."""

    #: Capability flag advertised in ``DriverMeta.capabilities``.
    CAPABILITY = "native_tools"

    @abstractmethod
    def get_native_tool_context(
        self, model_name: str | None = None,
    ) -> NativeToolContext: ...
