"""BaseDriver -- concrete base for hybrid drivers and orchestrators.

Delegates prompt generation to a ``PromptStrategy`` (codec) and
tool-call extraction to a chain of ``ExtractionStrategy`` instances.

Subclasses only need to implement ``list_tools()`` and
``execute_tool()`` from ``MCSToolDriver``.

All text that reaches the LLM is owned by the strategy, never
hardcoded in this module.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from .mcs_driver_interface import MCSDriver, DriverMeta, DriverResponse, ToolCallRecord
from .mcs_tool_driver_interface import MCSToolDriver, Tool
from .prompt_strategy import PromptStrategy
from .extraction_strategy import (
    ExtractionStrategy,
    ExtractedCall,
    TextExtractionStrategy,
    OpenAICompletionExtractionStrategy,
)
from .extraction_chain import ExtractionChain
from .llm_stream_buffer import LLMStreamBuffer
from .mixins.native_tools import SupportsNativeTools, NativeToolContext
from .mixins.streaming import SupportsStreaming

logger = logging.getLogger(__name__)


class BaseDriver(MCSDriver, MCSToolDriver, SupportsNativeTools, SupportsStreaming):
    """Concrete base that wires ``MCSDriver`` methods to a ``PromptStrategy``.

    Subclasses must provide:
    - ``list_tools() -> list[Tool]``
    - ``execute_tool(tool_name, arguments) -> Any``

    Everything else (prompt generation, LLM response parsing, retry
    handling) is inherited and driven by the strategy's TOML config.

    Tool-call extraction is handled by a chain of ``ExtractionStrategy``
    instances.  The default chain tries structured formats (dict-based)
    first, then falls back to the text codec.  Custom strategies can be
    injected via ``_extraction_strategies``.
    """

    def __init__(
        self,
        *,
        prompt_strategy: PromptStrategy | None = None,
        custom_tool_description: str | None = None,
        custom_system_message: str | None = None,
        _extraction_strategies: list[ExtractionStrategy] | None = None,
    ) -> None:
        self._strategy = prompt_strategy or PromptStrategy.default()
        self._custom_tool_description = custom_tool_description
        self._custom_system_message = custom_system_message
        self._extractors: list[ExtractionStrategy] = _extraction_strategies or [
            OpenAICompletionExtractionStrategy(),
            TextExtractionStrategy(self._strategy),
        ]
        # Shape-resolution + preferred-strategy cache live in the chain, so the
        # driver (extract) and the stream buffer (accumulate) share one instance.
        self._chain = ExtractionChain(self._extractors)

        # Capability flags are derived from the interfaces this driver implements
        # (MCSDriver -> "standalone", MCSToolDriver -> "orchestratable",
        # SupportsNativeTools -> "native_tools", …) and unioned with whatever the
        # driver's ``meta`` already declares -- so a driver may list them
        # explicitly for readability, leave them to be derived, or both.
        meta = getattr(type(self), "meta", None)
        if isinstance(meta, DriverMeta):
            self.meta = DriverMeta.derive_capabilities(meta, type(self))

    # -- MCSDriver contract ---------------------------------------------------

    def get_function_description(self, model_name: str | None = None) -> str:
        if self._custom_tool_description is not None:
            return self._custom_tool_description
        return self._strategy.format_tools(self.list_tools())

    def get_driver_system_message(self, model_name: str | None = None) -> str:
        if self._custom_system_message is not None:
            return self._custom_system_message
        return self._strategy.system_template.format(
            tools=self.get_function_description(model_name),
            call_example=self._strategy.format_call_example(),
        )

    def process_llm_response(
        self, llm_response: str | dict | LLMStreamBuffer,
    ) -> DriverResponse:
        # The *type* is the streaming signal: an LLMStreamBuffer means mid-stream
        # (only a stream-aware driver ever sees one); str | dict is the base path. The
        # owning strategy is resolved *once* here for both paths -- both converge on
        # _dispatch_tool_calls; the driver only ever asks "is there a call here that is
        # mine to run?", the ExtractionStrategy owns the format.
        message = (
            llm_response.as_dict()
            if isinstance(llm_response, LLMStreamBuffer)
            else llm_response
        )
        strategy = self._chain.resolve(message)
        if strategy is None:
            return DriverResponse()                  # no call recognised -> (stream: text flows)
        if isinstance(llm_response, LLMStreamBuffer):
            return self._process_stream(llm_response, strategy, message)
        return self._dispatch_tool_calls(strategy, message, strategy.extract(message))

    # -- Streaming --------------------------------------------------------------

    def _process_stream(
        self, buf: LLMStreamBuffer, strategy: ExtractionStrategy, message: str | dict,
    ) -> DriverResponse:
        """Hold while a call forms; decide as soon as it is complete.

        Once a strategy *recognises* a call (forming or complete), the driver holds
        the buffer -- reporting ``call_pending`` so the raw JSON/markup does not leak
        -- until :meth:`~ExtractionStrategy.extract` yields a runnable call. A native
        parallel batch grows until the stream's DONE signal (``buf.is_finished()``),
        so a ``batched`` strategy stays pending until then -- executing early would
        strand a still-streaming sibling. A text-embedded call is single and
        self-delimited (its closing fence completes it), so it resolves the moment it
        parses -- no waiting for the turn's end, so display isn't held longer than
        the call itself. Plain text (nothing recognised) simply flows.
        """
        calls = strategy.extract(message)
        if not calls or (strategy.batched and not buf.is_finished()):
            # A call forming for a tool I do not own -- a model *explaining* a call
            # rather than making one -- should flow as text, not be held. For a single
            # (non-batched) format, once its name has streamed in and is not one of my
            # tools, release now instead of holding the whole object.
            if not strategy.batched:
                name = strategy.forming_name(message)
                if name is not None and name not in {t.name for t in self.list_tools()}:
                    return DriverResponse()          # not mine -> flow as text
            buf.hold()                               # forming / batch not done -> suppress + pending
            return DriverResponse(call_pending=True)

        dr = self._dispatch_tool_calls(strategy, message, calls)
        if dr.call_executed or dr.call_failed:
            buf.reset()   # call consumed -- clear to hunt for the next
        return dr

    # -- Tool execution (one uniform path for every format) -------------------

    def _dispatch_tool_calls(
        self, strategy: ExtractionStrategy, message: str | dict,
        calls: list[ExtractedCall],
    ) -> DriverResponse:
        """Run the *calls* that are this driver's own; ignore the rest.

        The driver knows only itself: it keeps the calls it can run and executes
        those. Calls it does not own are left untouched -- silently (or via
        ``_no_owned``), because another driver in the client's list may own them
        (fan-out). The :class:`ExtractionStrategy` owns *how* the calls were found and
        *how* the result history is shaped, so this method never branches on native
        vs. text.
        """
        if not calls:
            return DriverResponse()

        known = {t.name for t in self.list_tools()}
        mine = [c for c in calls if c.name in known]
        if not mine:
            return DriverResponse()

        records = [self._invoke_tool(c) for c in mine]
        failed = [r for r in records if r.error is not None]
        return DriverResponse(
            call_executed=any(r.error is None for r in records),
            call_failed=bool(failed),
            executed_calls=records,
            messages=strategy.result_messages(message, records),
            tool_call_result=self._back_compat_result(records),
            retry_prompt=(
                self._strategy.retry_execution_failed(failed[0].name, failed[0].error or "")
                if failed else None
            ),
            call_detail=failed[0].error if failed else None,
        )    

    def _invoke_tool(self, call: ExtractedCall) -> ToolCallRecord:
        """Execute one owned call; capture the outcome as a :class:`ToolCallRecord`.

        A raised exception becomes ``record.error`` (it never propagates) -- the
        model reads the error back through ``result_messages`` and self-heals.
        """
        logger.info("Executing tool: %s", call.name)
        try:
            result = self.execute_tool(call.name, call.arguments)
            return ToolCallRecord(
                name=call.name, arguments=call.arguments,
                result=result, tool_call_id=call.id,
            )
        except Exception as e:
            return ToolCallRecord(
                name=call.name, arguments=call.arguments,
                error=f"Tool '{call.name}' failed: {e}", tool_call_id=call.id,
            )

    # -- Back-compat / helpers ------------------------------------------------

    @staticmethod
    def _back_compat_result(records: list[ToolCallRecord]) -> Any:
        """Legacy ``tool_call_result`` (superseded by ``executed_calls``).

        One successful call -> its result as text; several -> the raw list; ``None``
        when nothing ran successfully. Kept because existing examples still read it.
        """
        successes = [r for r in records if r.error is None]
        if not successes:
            return None
        if len(successes) == 1:
            return BaseDriver._result_text(successes[0].result)
        return [r.result for r in successes]

    @staticmethod
    def _result_text(result: Any) -> str:
        return result if isinstance(result, str) else json.dumps(result)

    # -- SupportsNativeTools implementation ------------------------------------

    def get_native_tool_context(
        self, model_name: str | None = None,
    ) -> NativeToolContext:
        """Return context for an LLM call.

        When *model_name* is given and the model supports native
        function-calling, the returned :class:`NativeToolContext` includes
        tool definitions in OpenAI format so the client can pass them
        as ``tools=ctx.tools``.  Otherwise, tools are embedded in
        ``system_message`` as text (the default MCS approach).
        """
        if model_name and self._model_supports_native_tools(model_name):
            return NativeToolContext(
                system_message=self._custom_system_message or "You are a helpful assistant.",
                tools=self._tools_as_native_dicts(),
            )
        return NativeToolContext(
            system_message=self.get_driver_system_message(model_name),
        )

    @staticmethod
    def _model_supports_native_tools(model_name: str) -> bool:
        """Check whether *model_name* supports native function-calling.

        Uses litellm if available, otherwise returns ``False``.

        .. todo::
            The dependency on ``litellm`` solely for this check is
            disproportionate.  Options under consideration:

            (a) Lightweight standalone package (e.g. ``mcs-model-registry``)
                that references / caches the ``litellm.model_cost`` JSON.
            (b) Explicit configuration – the capability is supplied from
                outside (e.g. via ``DriverMeta``, constructor parameter,
                or a pluggable registry).
            (c) Keep the status-quo lazy import (no hard dependency;
                graceful fallback to ``False``).

            Considerations: offline capability vs. freshness of model data.
            ``litellm`` itself may fetch ``model_cost`` from the network.
            Prompts are already designed to be loadable at runtime – a
            similar pattern could apply here.
        """
        # TODO: evaluate extraction of model-capability lookup (see docstring)
        try:
            from litellm import supports_function_calling  # type: ignore[import-untyped]
            return supports_function_calling(model=model_name)
        except Exception:
            return False

    def _tools_as_native_dicts(self) -> list[dict[str, Any]]:
        """Return tools as native API dicts via the active ``PromptStrategy``."""
        schemas = json.loads(self._strategy.format_tools(self.list_tools()))["tools"]
        return [{"type": "function", "function": s} for s in schemas]
