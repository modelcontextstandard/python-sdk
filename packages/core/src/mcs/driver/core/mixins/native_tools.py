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
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from ..extraction_strategy import TextExtractionStrategy


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

    @abstractmethod
    def set_native_backup_strategy(self, strategy: "TextExtractionStrategy | None") -> None:
        """Set (or clear with ``None``) the text strategy used when a native format leaks
        a call into its text; read back via :meth:`get_native_backup_strategy`. ``None``
        disables the leak fall-through, so a leaked call flows as text, uncaught."""

    @abstractmethod
    def get_native_backup_strategy(self) -> "TextExtractionStrategy | None":
        """The text strategy used when a native format leaks a call into its text.

        A model in native mode occasionally writes its call as text in the content
        channel instead of the native slot. For an envelope format whose message always
        carries its structure (Anthropic blocks, Responses items), the native strategy
        claims the shape but extracts no call; the driver then hands the message's plain
        text to this backup. Must be a text strategy (it is handed a plain string).

        The default is ``None`` (no leak backup); ``BaseDriver`` supplies the text
        strategy from its extraction chain.
        """
        return None
