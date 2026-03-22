"""Sandbox Driver — LLM-facing wrapper around the SandboxToolDriver.

This hybrid driver (``DriverBase`` + ``MCSToolDriver``) can be used
standalone (direct LLM conversation) or nested inside an Orchestrator.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from mcs.driver.core.base import DriverBase
from mcs.driver.core.mcs_driver_interface import DriverBinding, DriverMeta
from mcs.driver.core.mcs_tool_driver_interface import MCSToolDriver, Tool
from mcs.driver.core.prompt_strategy import PromptStrategy


@dataclass(frozen=True)
class _SandboxDriverMeta(DriverMeta):
    id: str = "b2c3d4e5-sb02-4000-9000-sandbox00000002"
    name: str = "Sandbox MCS Driver"
    version: str = "0.1.0"
    bindings: tuple = (
        DriverBinding(
            capability="sandbox", adapter="*", spec_format="Custom"
        ),
    )
    supported_llms: tuple = ("*",)
    capabilities: tuple = ("standalone", "orchestratable")


class SandboxDriver(DriverBase):
    """Full MCS Driver that gives an LLM access to an isolated sandbox.

    Parameters
    ----------
    adapter : str
        Backend identifier (``"docker"``, future: ``"ssh"``, ``"e2b"``).
    custom_tool_description : str | None
        Override the auto-generated tool description.
    custom_driver_system_message : str | None
        Override the default system message.
    prompt_strategy : PromptStrategy | None
        Custom prompt codec.
    _tooldriver : MCSToolDriver | None
        Pre-built ToolDriver (for testing / DI).
    **adapter_kwargs
        Forwarded to the adapter constructor.
    """

    meta: DriverMeta = _SandboxDriverMeta()

    def __init__(
        self,
        *,
        adapter: str = "docker",
        custom_tool_description: Optional[str] = None,
        custom_driver_system_message: Optional[str] = None,
        prompt_strategy: Optional[PromptStrategy] = None,
        _tooldriver: Optional[MCSToolDriver] = None,
        **adapter_kwargs: Any,
    ) -> None:
        super().__init__(
            prompt_strategy=prompt_strategy,
            custom_tool_description=custom_tool_description,
            custom_system_message=custom_driver_system_message,
        )
        if _tooldriver is not None:
            self._td = _tooldriver
        else:
            from mcs.driver.sandbox.tooldriver import SandboxToolDriver

            self._td = SandboxToolDriver(adapter=adapter, **adapter_kwargs)

    # -- Delegate to ToolDriver -------------------------------------------

    def list_tools(self) -> List[Tool]:
        return self._td.list_tools()

    def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        return self._td.execute_tool(tool_name, arguments)
