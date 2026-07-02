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
    TextExtractionStrategy,
    OpenAICompletionExtractionStrategy,
)
from .extraction_chain import ExtractionChain
from .llm_stream_buffer import LLMStreamBuffer
from .mixins.native_tools import SupportsNativeTools, NativeToolContext
from .mixins.streaming import SupportsStreaming

logger = logging.getLogger(__name__)

#: Sentinel returned by ``_extract`` when a strategy claimed the response's
#: format but no complete tool call could be parsed (yet). Distinct from
#: ``None`` (= no tool call at all) -- the difference is what lets streaming
#: tell "keep buffering" from "plain text".
_INCOMPLETE: object = object()


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
        if isinstance(llm_response, LLMStreamBuffer):
            return self._process_stream(llm_response)

        parsed = self._extract(llm_response)
        if parsed is _INCOMPLETE or parsed is None:
            # Non-streaming: an incomplete/absent call is simply "no call".
            return DriverResponse()

        assert isinstance(parsed, tuple)   # narrowed: not _INCOMPLETE, not None
        tool_name, arguments = parsed
        native_call = None
        if isinstance(llm_response, dict) and llm_response.get("tool_calls"):
            native_call = llm_response["tool_calls"][0]
        return self._run_tool(
            tool_name, arguments, self._llm_text(llm_response), native_call=native_call,
        )

    # -- Streaming --------------------------------------------------------------

    def _process_stream(self, buf: LLMStreamBuffer) -> DriverResponse:
        """Process the accumulated stream so far; do the "magic" on the buffer.

        Native tool calls are **batched**: a provider may emit several in parallel
        (``tool_calls[0..n]``), and we only know the batch is complete at the
        turn's DONE signal (``buf.is_finished()`` -- ``finish_reason`` /
        ``response.completed`` / ``message_stop``). So while the turn streams we
        report ``call_pending``; once finished we execute **all** the calls at once
        and feed each result back by its ``tool_call_id``. Executing ``[0]`` early
        (before the siblings arrive) is exactly what stranded the parallel calls.

        A text-embedded call is single and resolves as soon as the codec parses it.
        Display stays with the buffer -- the client reads ``buf.text()``.
        """
        if buf.has_tool_call():
            if not buf.is_finished():
                return DriverResponse(call_pending=True)   # batch still forming
            return self._run_native_batch(buf)

        # No native tool_calls: a text-embedded call (or plain text).
        parsed = self._extract(buf.as_dict())
        if parsed is _INCOMPLETE:
            return DriverResponse(call_pending=True)
        if parsed is None:
            return DriverResponse()

        assert isinstance(parsed, tuple)
        tool_name, arguments = parsed
        dr = self._run_tool(tool_name, arguments, buf.get_content() or "")
        if dr.call_executed or dr.call_failed:
            buf.reset()   # text call consumed -- clear to hunt for the next
        return dr

    # -- Tool execution (shared by both paths) --------------------------------

    @staticmethod
    def _llm_text(llm_response: str | dict) -> str:
        if isinstance(llm_response, str):
            return llm_response
        return llm_response.get("content") or json.dumps(llm_response)

    def _run_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        llm_text: str,
        *,
        native_call: dict[str, Any] | None = None,
    ) -> DriverResponse:
        # ``native_call`` is the raw tool-call dict (with its ``id``) when the call
        # came in native form. The result must then be fed back in native shape --
        # an assistant message carrying the ``tool_calls`` and a ``role="tool"``
        # result keyed by ``tool_call_id`` -- so the model sees its call answered
        # (a ``system`` message with the raw text does not close a native call).
        known = {t.name for t in self.list_tools()}
        tc_id = (native_call or {}).get("id")

        if tool_name not in known:
            if self._strategy.unknown_tool_behavior == UnknownToolBehavior.RETRY_WITH_LIST:
                available = ", ".join(sorted(known))
                retry = self._strategy.retry_unknown_tool(tool_name, available)
                detail = f"No matching tool '{tool_name}' found."
                return DriverResponse(
                    call_failed=True,
                    call_detail=detail,
                    retry_prompt=retry,
                    messages=[
                        {"role": "assistant", "content": llm_text},
                        {"role": "system", "content": retry},
                    ],
                    executed_calls=[ToolCallRecord(
                        name=tool_name, arguments=arguments, error=detail, tool_call_id=tc_id,
                    )],
                )
            return DriverResponse()

        logger.info("Executing tool: %s", tool_name)

        try:
            result = self.execute_tool(tool_name, arguments)
            result_text = result if isinstance(result, str) else json.dumps(result)
        except Exception as e:
            retry = self._strategy.retry_execution_failed(tool_name, str(e))
            detail = f"Tool '{tool_name}' failed: {e}"
            return DriverResponse(
                call_failed=True,
                call_detail=detail,
                retry_prompt=retry,
                messages=[
                    {"role": "assistant", "content": llm_text},
                    {"role": "system", "content": retry},
                ],
                executed_calls=[ToolCallRecord(
                    name=tool_name, arguments=arguments, error=detail, tool_call_id=tc_id,
                )],
            )

        if native_call is not None:
            messages = [
                {"role": "assistant", "content": None, "tool_calls": [native_call]},
                {"role": "tool", "tool_call_id": tc_id, "content": result_text},
            ]
        else:
            messages = [
                {"role": "assistant", "content": llm_text},
                {"role": "system", "content": result_text},
            ]

        return DriverResponse(
            tool_call_result=result_text,
            call_executed=True,
            messages=messages,
            executed_calls=[ToolCallRecord(
                name=tool_name, arguments=arguments, result=result, tool_call_id=tc_id,
            )],
        )

    def _run_native_batch(self, buf: LLMStreamBuffer) -> DriverResponse:
        """Execute *all* native tool calls in the finished batch, native-shaped.

        OpenAI requires a ``role="tool"`` result for **every** ``tool_call`` in the
        assistant message, so each call gets one -- successes carry the result,
        failures carry the error (the model self-heals from that). The assistant
        message carries the whole ``tool_calls`` array; the buffer is cleared after.
        """
        known = {t.name for t in self.list_tools()}
        tool_calls = buf.get_tool_calls()

        assistant_msg: dict[str, Any] = {
            "role": "assistant",
            "content": buf.get_content(),
            "tool_calls": tool_calls,
        }
        tool_msgs: list[dict[str, Any]] = []
        records: list[ToolCallRecord] = []
        for tc in tool_calls:
            record = self._exec_native_one(tc, known)
            records.append(record)
            content = record.error if record.error is not None else self._result_text(record.result)
            tool_msgs.append(
                {"role": "tool", "tool_call_id": record.tool_call_id, "content": content}
            )

        buf.reset()
        return DriverResponse(
            call_executed=True,
            call_failed=any(r.error is not None for r in records),
            messages=[assistant_msg, *tool_msgs],
            executed_calls=records,
            tool_call_result=(  # back-compat: first result, or the list
                records[0].result if len(records) == 1 else [r.result for r in records]
            ),
        )

    def _exec_native_one(self, tc: dict[str, Any], known: set[str]) -> ToolCallRecord:
        """Run one native tool call; return a :class:`ToolCallRecord`.

        Native errors are carried on the record (and become that call's tool-result
        content) -- the model reads them and self-heals; no client-side retry prompt.
        """
        fn = tc.get("function") or {}
        name = fn.get("name") or ""
        tc_id = tc.get("id")

        arguments, parse_error = self._parse_args(fn.get("arguments", "{}"))
        if parse_error is not None:
            return ToolCallRecord(name=name, arguments={}, error=parse_error, tool_call_id=tc_id)
        if not name or name not in known:
            return ToolCallRecord(
                name=name, arguments=arguments,
                error=f"No matching tool '{name}'.", tool_call_id=tc_id,
            )

        logger.info("Executing tool: %s", name)
        try:
            result = self.execute_tool(name, arguments)
            return ToolCallRecord(name=name, arguments=arguments, result=result, tool_call_id=tc_id)
        except Exception as e:
            return ToolCallRecord(
                name=name, arguments=arguments,
                error=f"Tool '{name}' failed: {e}", tool_call_id=tc_id,
            )

    @staticmethod
    def _parse_args(raw: Any) -> tuple[dict[str, Any], str | None]:
        """Return ``(arguments, error)`` -- parse a JSON-string / dict argument blob."""
        if isinstance(raw, dict):
            return raw, None
        if isinstance(raw, str):
            stripped = raw.strip()
            if not stripped:
                return {}, None
            try:
                return json.loads(stripped), None
            except json.JSONDecodeError:
                return {}, "Could not parse arguments."
        return {}, None

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

    # -- Extraction chain -----------------------------------------------------

    def _extract(
        self, llm_response: str | dict,
    ) -> tuple[str, dict[str, Any]] | object | None:
        """Resolve the owning strategy via the chain, then extract.

        :class:`ExtractionChain` finds the strategy whose *shape* matches
        (``recognizes``) and caches it; this driver then calls ``extract``
        on the winner.  A recognised strategy that yields no complete call
        returns :data:`_INCOMPLETE` -- distinct from ``None`` (no call at
        all) -- so streaming can tell "keep buffering" from "plain text".
        When nothing claims the shape, the chain's text fallback is used.
        """
        strategy = self._chain.resolve(llm_response)
        if strategy is not None:
            result = strategy.extract(llm_response)
            return result if result is not None else _INCOMPLETE

        fallback = self._chain.text_fallback
        if fallback is not None:
            return fallback.extract(llm_response)
        return None
