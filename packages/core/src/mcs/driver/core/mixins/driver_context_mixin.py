"""Optional mixin for drivers that support native tool-calling via ``get_driver_context``.

When an LLM API supports native function-calling (OpenAI ``tools`` parameter,
Anthropic ``tools``, etc.), the client needs more than just a system-message
string -- it also needs the tool definitions as structured dicts.

``SupportsDriverContext`` solves this by providing ``get_driver_context()``,
which returns a :class:`DriverContext` containing the system message *and*
optionally the native tool definitions.

The mixin is **opt-in** via ``DriverBase`` (which includes it by default)
or by explicit inheritance.  Clients detect support via
``"driver_context" in driver.meta.capabilities`` or
``isinstance(driver, SupportsDriverContext)``.

The capability ``"driver_context"`` is **automatically registered** in the
driver's ``DriverMeta.capabilities`` via ``__init_subclass__``.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from ..mcs_driver_interface import DriverMeta

_CAPABILITY = "driver_context"


@dataclass
class DriverContext:
    """Everything a client needs to initialise an LLM call.

    Attributes
    ----------
    system_message :
        The system prompt text.  Always present.
    tools :
        Optional list of native tool definitions in OpenAI function-calling
        format.  When set, the client should pass these as the ``tools``
        parameter of the LLM API call instead of relying on tools embedded
        in the system message text.  ``None`` means the tools are already
        encoded inside ``system_message``.
    """
    system_message: str
    tools: list[dict[str, Any]] | None = None


class SupportsDriverContext:
    """Opt-in mixin: provide ``get_driver_context()`` for native tool-calling.

    When a class inherits from this mixin, ``__init_subclass__``
    automatically adds ``"driver_context"`` to the driver's
    ``meta.capabilities`` tuple -- no manual registration needed.
    """

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        _auto_register_capability(cls, _CAPABILITY)

    def get_driver_context(
        self, model_name: str | None = None,
    ) -> DriverContext:
        """Return context for an LLM call (system message + optional native tools).

        The default implementation delegates to ``get_driver_system_message``
        and returns tools as ``None`` (text-prompt mode).  Subclasses or
        ``DriverBase`` may override to supply native tool definitions when
        the target model supports function-calling.

        Parameters
        ----------
        model_name :
            Optional target LLM name.  Implementations may use this to
            decide whether to return native tools or text-based prompts.
        """
        system_msg = getattr(self, "get_driver_system_message", None)
        if system_msg is not None and callable(system_msg):
            return DriverContext(system_message=str(system_msg(model_name)))
        return DriverContext(system_message="")


def _auto_register_capability(cls: type, capability: str) -> None:
    """Add *capability* to the ``meta.capabilities`` of *cls* if not present.

    Discovery order:
    1. Check ``cls.meta`` directly (convention).
    2. Search ``cls`` attributes for any ``DriverMeta`` instance (fallback).
    """
    from ..mcs_driver_interface import DriverMeta

    meta: DriverMeta | None = None
    meta_attr: str | None = None

    # Fast path: convention-based lookup
    val = getattr(cls, "meta", None)
    if isinstance(val, DriverMeta):
        meta = val
        meta_attr = "meta"
    else:
        # Fallback: search class dict for any DriverMeta instance
        for name, val in vars(cls).items():
            if isinstance(val, DriverMeta):
                meta = val
                meta_attr = name
                break

    if meta is None or meta_attr is None:
        return

    if capability not in meta.capabilities:
        setattr(
            cls,
            meta_attr,
            replace(meta, capabilities=(*meta.capabilities, capability)),
        )
