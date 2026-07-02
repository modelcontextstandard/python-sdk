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
from .prompt_strategy import PromptStrategy, UnknownToolBehavior
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
        # (only a stream-aware driver ever sees one); str | dict is the base path.
        # Both converge on _execute_tools -- the driver only ever asks "is there a
        # call here that is mine to run?"; the ExtractionStrategy owns the format.
        if isinstance(llm_response, LLMStreamBuffer):
            return self._process_stream(llm_response)
        return self._process_message(llm_response)

    # -- Streaming --------------------------------------------------------------

    def _process_stream(self, buf: LLMStreamBuffer) -> DriverResponse:
        """Gate execution on the stream's completion, then run the uniform path.

        A native batch may carry several parallel calls that only complete at the
        turn's DONE signal (``buf.is_finished()`` -- ``finish_reason`` /
        ``response.completed`` / ``message_stop``); until then any forming call is
        reported as ``call_pending`` -- executing early strands the siblings still
        streaming. A text-embedded call has no batch and runs as soon as the codec
        parses it. Both distinctions live in the *strategy* (``is_forming`` /
        ``extract``), not in a native-vs-text branch here. Display stays with the
        buffer -- the client reads ``buf.text()``.

        The pending gate is the one thing streaming adds over the base path; the
        resolved strategy is then reused for :meth:`_execute_tools`, so this path --
        like the non-streaming one -- resolves exactly once.
        """
        message = buf.as_dict()
        strategy = self._chain.resolve(message) or self._chain.text_fallback
        if strategy is None:
            return DriverResponse()
        if strategy.is_forming(message) and not buf.is_finished():
            return DriverResponse(call_pending=True)

        dr = self._execute_tools(strategy, message)
        if dr.call_executed or dr.call_failed:
            buf.reset()   # call consumed -- clear to hunt for the next
        return dr

    # -- Tool execution (one uniform path for every format) -------------------

    def _process_message(self, message: str | dict) -> DriverResponse:
        """Non-streaming entry: resolve the owning strategy, then run its calls."""
        strategy = self._chain.resolve(message) or self._chain.text_fallback
        if strategy is None:
            return DriverResponse()
        return self._execute_tools(strategy, message)

    def _execute_tools(
        self, strategy: ExtractionStrategy, message: str | dict,
    ) -> DriverResponse:
        """Run the calls in *message* that are this driver's own; ignore the rest.

        The driver knows only itself: it extracts every call the format carries,
        keeps the ones it can run, and executes those. Calls it does not own are
        left untouched -- silently, because another driver in the client's list may
        own them (fan-out). The :class:`ExtractionStrategy` owns *how* the calls are
        found and *how* the result history is shaped, so this method never branches
        on native vs. text. *strategy* is passed in already resolved so each entry
        point (streaming / non-streaming) resolves exactly once.
        """
        calls = strategy.extract(message)
        if not calls:
            return DriverResponse()

        known = {t.name for t in self.list_tools()}
        mine = [c for c in calls if c.name in known]
        if not mine:
            return self._no_owned(calls, message)

        records = [self._run_one(c) for c in mine]
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

    def _no_owned(
        self, calls: list[ExtractedCall], message: str | dict,
    ) -> DriverResponse:
        """No call was this driver's own.

        Default (fan-out safe): stay silent -- the calls belong to no tool of ours,
        so return an empty response and let another driver in the list handle them.
        When the codec opts into ``RETRY_WITH_LIST`` (single-driver self-heal), nudge
        the model with the tools it *does* have instead of ignoring the call.
        """
        if self._strategy.unknown_tool_behavior == UnknownToolBehavior.RETRY_WITH_LIST and calls:
            bad = calls[0]
            available = ", ".join(sorted(t.name for t in self.list_tools()))
            retry = self._strategy.retry_unknown_tool(bad.name, available)
            detail = f"No matching tool '{bad.name}' found."
            return DriverResponse(
                call_failed=True,
                call_detail=detail,
                retry_prompt=retry,
                messages=[
                    {"role": "assistant", "content": self._llm_text(message)},
                    {"role": "system", "content": retry},
                ],
                executed_calls=[ToolCallRecord(
                    name=bad.name, arguments=bad.arguments, error=detail,
                )],
            )
        return DriverResponse()

    def _run_one(self, call: ExtractedCall) -> ToolCallRecord:
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
    def _llm_text(message: str | dict) -> str:
        """The assistant-visible text of a message, for a retry echo."""
        if isinstance(message, str):
            return message
        return message.get("content") or json.dumps(message)

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
