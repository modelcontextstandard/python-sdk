"""Bash Driver -- LLM-facing wrapper around the BashToolDriver.

This hybrid driver (``BaseDriver`` + ``MCSToolDriver``) can be used standalone
(direct LLM conversation) or nested inside an Orchestrator.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from mcs.driver.core import BaseDriver
from mcs.driver.core.mcs_driver_interface import DriverBinding, DriverMeta
from mcs.driver.core.mcs_tool_driver_interface import MCSToolDriver, Tool
from mcs.driver.core.prompt_strategy import PromptStrategy

from .ports import ExecutorPort
from .tooldriver import BashToolDriver


@dataclass(frozen=True)
class _BashDriverMeta(DriverMeta):
    id: str = "b2c3d4e5-ba02-4000-9000-bash00000002"
    name: str = "Bash MCS Driver"
    version: str = "0.2.0"
    bindings: tuple = (
        DriverBinding(capability="bash", adapter="*", spec_format="Custom"),
    )
    supported_llms: tuple = ("*",)
    capabilities: tuple = ("standalone", "orchestratable")


class BashDriver(BaseDriver):
    """Full MCS Driver that gives an LLM a shell over an injected executor.

    Parameters
    ----------
    executor :
        The execution modality (LocalAdapter, DockerAdapter, SSHAdapter, ...)
        -- injected, never constructed here. See
        :class:`~mcs.driver.bash.BashToolDriver`.
    custom_tool_description : str | None
        Override the auto-generated tool description.
    custom_driver_system_message : str | None
        Override the default system message.
    prompt_strategy : PromptStrategy | None
        Custom prompt codec.
    _tooldriver : MCSToolDriver | None
        Pre-built ToolDriver (for testing / DI).
    **tool_kwargs
        Forwarded to :class:`BashToolDriver` (default_timeout, max_timeout,
        max_output_chars).
    """

    meta: DriverMeta = _BashDriverMeta()

    def __init__(
        self,
        executor: Optional[ExecutorPort] = None,
        *,
        custom_tool_description: Optional[str] = None,
        custom_driver_system_message: Optional[str] = None,
        prompt_strategy: Optional[PromptStrategy] = None,
        _tooldriver: Optional[MCSToolDriver] = None,
        **tool_kwargs: Any,
    ) -> None:
        super().__init__(
            prompt_strategy=prompt_strategy,
            custom_tool_description=custom_tool_description,
            custom_system_message=custom_driver_system_message,
        )
        if _tooldriver is not None:
            self._td = _tooldriver
        elif executor is not None:
            self._td = BashToolDriver(executor, **tool_kwargs)
        else:
            raise ValueError(
                "BashDriver needs an executor -- where commands run is a "
                "choice the client makes, never a silent default."
            )

    # -- Delegate to ToolDriver -------------------------------------------

    def list_tools(self) -> List[Tool]:
        return self._td.list_tools()

    def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        return self._td.execute_tool(tool_name, arguments)
