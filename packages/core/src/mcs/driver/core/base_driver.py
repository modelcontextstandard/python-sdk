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
from typing import Any, Callable

from .mcs_driver_interface import MCSDriver, DriverMeta, DriverResponse, ToolCallRecord
from .mcs_tool_driver_interface import MCSToolDriver, Tool
from .prompt_strategy import PromptStrategy
from .extraction_strategy import (
    ExtractionStrategy,
    ExtractedCall,
    Forming,
    TextExtractionStrategy,
    OpenAICompletionExtractionStrategy,
    OpenAIResponseExtractionStrategy,
    AnthropicExtractionStrategy,
)
from .extraction_chain import ExtractionChain
from .llm_stream_buffer import LLMStreamBuffer
from .mixins.native_tools import SupportsNativeTools, NativeToolContext
from .mixins.streaming import SupportsStreaming
from .mixins.tool_middleware import ToolMiddleware, SupportsToolMiddleware

logger = logging.getLogger(__name__)


class BaseDriver(
    MCSDriver, MCSToolDriver, SupportsNativeTools, SupportsStreaming, SupportsToolMiddleware,
):
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
        middleware: list[ToolMiddleware] | None = None,
        _extraction_strategies: list[ExtractionStrategy] | None = None,
        _chain: ExtractionChain | None = None,
    ) -> None:
        self._prompt_strategy = prompt_strategy or PromptStrategy.default()
        self._custom_tool_description = custom_tool_description
        self._custom_system_message = custom_system_message
        # The one shared chain: every native wire (so the driver can extract a call
        # from any provider's native message the buffer reassembled) followed by one
        # text codec (JSON, the ~99.9% case). A developer adds Hermes/XML/Ollama as one
        # more entry. The buffer resolves *reassembly* over these; the driver resolves
        # *extraction* over the same list -- two axes, one list.
        self._extractors: list[ExtractionStrategy] = _extraction_strategies or [
            OpenAICompletionExtractionStrategy(),
            OpenAIResponseExtractionStrategy(),
            AnthropicExtractionStrategy(),
            TextExtractionStrategy(self._prompt_strategy),
        ]
        self._chain = _chain or ExtractionChain(self._extractors)
        self._native_backup = TextExtractionStrategy(self._prompt_strategy)

        # Cross-cutting concerns (hooks, permission, auth) as an ordered middleware chain
        # around execute_tool (SupportsToolMiddleware) -- outermost first. Middleware lives
        # *inside* the driver, so the driver keeps its identity and clients use isinstance.
        self._middleware: list[ToolMiddleware] = list(middleware or [])

        # Capability flags are derived from the interfaces this driver implements
        # (MCSDriver -> "standalone", MCSToolDriver -> "orchestratable",
        # SupportsNativeTools -> "native_tools", …) unioned with whatever the driver's
        # ``meta`` already declares. Purely static: the data sheet describes the driver
        # *class*, so which middleware an instance happens to run stays out of it --
        # that is runtime configuration the client made, not a property of the driver.
        meta = getattr(type(self), "meta", None)
        if isinstance(meta, DriverMeta):
            self.meta = meta.derive_capabilities(type(self))

    # -- MCSDriver contract ---------------------------------------------------

    def get_function_description(self, model_name: str | None = None) -> str:
        if self._custom_tool_description is not None:
            return self._custom_tool_description
        return self._prompt_strategy.format_tools(self.list_tools())

    def get_driver_system_message(self, model_name: str | None = None) -> str:
        if self._custom_system_message is not None:
            return self._custom_system_message
        return self._prompt_strategy.system_template.format(
            tools=self.get_function_description(model_name),
            call_example=self._prompt_strategy.format_call_example(),
        )

    def process_llm_response(
        self, llm_response: str | dict | LLMStreamBuffer,
    ) -> DriverResponse:
        # The *type* is the streaming signal: an LLMStreamBuffer means mid-stream
        # (only a stream-aware driver ever sees one); str | dict is the base path. The
        # driver resolves the *extraction* axis on the assembled message here (the buffer
        # already resolved the *reassembly* axis on the raw chunks) -- two different
        # questions on the one shared chain. Both paths converge on _dispatch_tool_calls;
        # the driver only ever asks "is there a call here that is mine to run?", the
        # ExtractionStrategy owns the format.
        message = (
            llm_response.as_dict()
            if isinstance(llm_response, LLMStreamBuffer)
            else llm_response
        )
        strategy = self._chain.resolve(message)
        if strategy is None:
            return DriverResponse()                  # no format recognised -> (stream: text flows)
        if isinstance(llm_response, LLMStreamBuffer):
            return self._process_stream(llm_response, strategy, message)
        eff, emsg, _forming, calls = self._resolve_calls(strategy, message)
        return self._dispatch_tool_calls(eff, emsg, calls)

    # -- Extraction (with the native->text leak fall-through) -----------------

    def _resolve_calls(
        self, strategy: ExtractionStrategy, message: str | dict,
    ) -> tuple[ExtractionStrategy, str | dict, Forming, list[ExtractedCall]]:
        """Resolve the calls in *message*: their forming state and finished call(s).

        Returns ``(effective_strategy, effective_message, forming, calls)``. A model in
        native mode occasionally *leaks* its call as text instead of the native slot. For
        an envelope format whose message always carries its structure (``leaks_into_text``)
        the native strategy claims the shape but is neither forming nor extracting a call
        -- so the driver hands the message's plain text
        (:meth:`~ExtractionStrategy.content_text`) to the text backup. If the backup sees a
        call (forming or complete), *it* becomes the effective strategy (and shapes the
        result history: a leaked call opened no native id, so the model expects a
        text-style continuation).
        """
        # First, the normal path: ask the resolved format for its complete calls and
        # whether one is forming.
        calls = strategy.extract(message)
        forming = strategy.forming(message)

        # We are done in the common cases -- use this strategy's answer as-is when:
        #   - it found complete calls, OR
        #   - it sees one forming, OR
        #   - this format cannot hide a call in its text anyway (leaks_into_text is False,
        #     e.g. OpenAI Completions: a leak has no tool_calls key, so the chain already
        #     routed it straight to the text strategy -- no fall-through needed).
        if calls or forming or not strategy.leaks_into_text:
            return strategy, message, forming, calls

        # Otherwise we are in the leak case. The format is an envelope one whose message
        # ALWAYS carries its structure (Anthropic blocks / Responses items), so it claimed
        # the shape -- but found nothing. The call may be sitting in a *text* block (the
        # model wrote it as prose instead of the native slot). Hand that plain text to the
        # backup text strategy and let it look.
        backup = self.get_native_backup_strategy()
        if backup is None:                               # backup disabled -> give up, no call
            return strategy, message, forming, calls
        text = strategy.content_text(message)            # the message's plain text
        b_calls, b_forming = backup.extract(text), backup.forming(text)
        if b_calls or b_forming:
            # The backup found the leaked call. It becomes the *effective* strategy, and
            # `text` the effective message -- so extraction AND the result history come
            # from the text codec (a leaked call opened no native id, so the model expects
            # a plain text-style answer, not a native tool result).
            return backup, text, b_forming, b_calls
        return strategy, message, forming, calls         # truly nothing here


    def set_native_backup_strategy(self, strategy: TextExtractionStrategy | None) -> None:
        """Set (or clear with ``None``) the leak backup. ``None`` disables the
        native→text fall-through -- a leaked call then flows as text, uncaught."""
        self._native_backup = strategy

    def get_native_backup_strategy(self) -> TextExtractionStrategy | None:
        """The text strategy used when a native format claims but extracts no call.

        Fulfils the ``SupportsNativeTools`` leak-backup concern. Defaults to the text
        strategy in this driver's chain; a driver may override to supply a different one.
        Must be a text strategy (it is handed a plain string). 
        """             
        return self._native_backup

    def extraction_strategies(self) -> list[ExtractionStrategy]:
        """This driver's extraction chain (``SupportsStreaming``).

        Handed to a stream buffer so it reassembles over the same strategies the driver
        extracts with -- one shared list, two axes. See :meth:`new_stream_buffer`.
        """
        return list(self._extractors)

    # -- Streaming --------------------------------------------------------------

    def _process_stream(
        self, buf: LLMStreamBuffer, strategy: ExtractionStrategy, message: str | dict,
    ) -> DriverResponse:
        """Hold while a call *forms*; decide as soon as it is complete; else flow.

        Three outcomes, in order: (1) a runnable call is ready -> execute it and clear the
        buffer; a ``batched`` native strategy waits for the stream's DONE signal
        (``buf.is_finished()``) first, so a still-streaming parallel sibling is never
        stranded. (2) no call yet but one is :meth:`~ExtractionStrategy.forming` -> hold
        the buffer (``call_pending``) so the raw JSON/markup does not leak into display --
        unless the forming call already names a tool this driver does not own (a model
        *explaining* a call), which is released early as text. (3) not forming -> plain
        text (prose, or a final answer) simply flows.
        """
        # Ask the format expert two questions about the message assembled so far:
        #   forming -> "is a tool call on its way here?" (+ its name once it has streamed in)
        #   calls   -> "which *complete*, runnable calls are in here right now?" ([] if none)
        # (eff/emsg usually equal strategy/message; they differ only when a native format
        #  leaked its call into text -- then eff is the text backup, emsg that plain text.)
        eff, emsg, forming, calls = self._resolve_calls(strategy, message)

        # How far the content is *settled*: past every complete object (a call OR a
        # non-call the model narrated) and its fence, before any still-forming block. The
        # driver advances the buffer past this each round -- otherwise a settled non-call
        # at the front (an example, an unknown format like ``recipient_name``) would stay
        # there and anchor the scan on itself, hiding the block after it. ``0`` for native
        # (no text offset -> such a batch resets the whole message).
        settled = eff.settled_end(emsg)

        # ── Outcome 1: a complete call is ready -> run it now ───────────────────────────
        # Enter when there IS at least one complete call AND we are allowed to run it yet.
        # The second half is the "batched gate":
        #   - A text call is self-delimiting (its closing } / fence finishes it), so
        #     eff.batched is False and the gate is always open -> run immediately.
        #   - Native parallel calls arrive as a *growing batch* (eff.batched is True). We
        #     must wait for the stream's DONE signal (buf.is_finished()), else a sibling
        #     call still streaming would be cut off -> run only once the batch is finished.
        #   Read `not (batched and not finished)` as: "not a batch that isn't done yet".
        if calls and not (eff.batched and not buf.is_finished()):
            # Run the calls that are MINE; silently ignore the rest (in a chain of drivers
            # another one may own them). `dr` carries the results, the history to feed back,
            # and the status flags.
            dr = self._dispatch_tool_calls(eff, emsg, calls)

            # Move the buffer PAST everything settled this round, so the *next* block is not
            # shadowed. ``settled`` covers the calls we just handled (mine, executed) AND any
            # foreign / non-call object among them -- foreign ones are dropped too, but the
            # buffer defers the actual drop to the next add(), so a driver that DOES own them
            # still sees them this round first (that is what makes it fan-out-safe). Text
            # advances by offset (keeping the tail -- the next call / prose); a native batch
            # has no text offset (settled == 0) and *is* the whole message, so it goes whole.
            # Both are deferred -- never buf.reset(), which drops at once and would let the
            # first driver in a chain wipe a call the second one owns.
            if settled:
                buf.consume_through(settled)
            else:
                buf.consume_all()
            return dr

        # ── No runnable call this round: either something is forming, or it is plain text.
        # Either way, drop any settled non-call block(s) at the front (an example the model
        # narrated, an unknown format) so the tail is parsed fresh next round -- deferred and
        # fan-out-safe, exactly like a handled call.
        if settled:
            buf.consume_through(settled)

        # ── Outcome 2: nothing is forming -> ordinary text (prose, or the final answer).
        # Return an empty DriverResponse ("no call of mine here") so the buffer's text flows
        # to the display.
        if not forming:
            return DriverResponse()

        # ── Outcome 3: a call IS forming, its name has already streamed in, and it is NOT
        # one of my tools -> the model is *explaining / quoting* a call, not making one.
        # Release it as text (flow) instead of holding. Only for a single text call: a
        # native batch is already committed to a real call, so we never second-guess it.
        if not eff.batched and forming.tool_name and (
            forming.tool_name not in {t.name for t in self.list_tools()}
        ):
            return DriverResponse()

        # ── Outcome 4: a call is forming and is (or might still turn out to be) mine ->
        # HOLD the buffer: suppress display so the half-written JSON/markup never leaks,
        # and report call_pending so the client can show "…" and keep streaming.
        buf.hold()
        return DriverResponse(call_pending=True)

    # -- Tool execution (one uniform path for every format) -------------------

    def _dispatch_tool_calls(
        self, strategy: ExtractionStrategy, message: str | dict,
        calls: list[ExtractedCall],
    ) -> DriverResponse:
        """Run the *calls* that are this driver's own; ignore the rest.

        The driver knows only itself: it keeps the calls it can run and executes
        those. Calls it does not own are left untouched -- silently, because another
        driver in the client's list may own them (fan-out). The :class:`ExtractionStrategy`
        owns *how* the calls were found and *how* the result history is shaped, so this
        method never branches on native vs. text. *calls* are already extracted (with any
        leak fall-through applied by :meth:`_extract`).
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
            retry_prompt=(
                self._prompt_strategy.retry_execution_failed(failed[0].name, failed[0].error or "")
                if failed else None
            ),
        )

    def _invoke_tool(self, call: ExtractedCall) -> ToolCallRecord:
        """Execute one owned call through the middleware chain; capture the outcome.

        A raised exception becomes ``record.error`` (it never propagates) -- the model
        reads the error back through ``result_messages`` and self-heals. The chain runs
        *inside* this try/except, so a concern that does not catch a domain error (e.g. an
        auth challenge with no ``AuthMiddleware`` present) still degrades to ``call_failed``
        rather than crashing -- the exact fallback the old decorator stack had.
        """
        logger.info("Executing tool: %s", call.name)
        try:
            result = self._run_tool_chain(call.name, call.arguments)
            return ToolCallRecord(
                name=call.name, arguments=call.arguments,
                result=result, tool_call_id=call.id,
            )
        except Exception as e:
            return ToolCallRecord(
                name=call.name, arguments=call.arguments,
                error=f"Tool '{call.name}' failed: {e}", tool_call_id=call.id,
            )

    def _run_tool_chain(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        """Run *tool_name* through the middleware chain, ending at :meth:`execute_tool`.

        The chain is built outermost-first: ``self._middleware[0]`` wraps everything, so
        it sees the call first and the result last. With no middleware this is just
        ``execute_tool`` -- zero overhead.
        """
        call_next: "Callable[[str, dict[str, Any]], Any]" = self.execute_tool
        for mw in reversed(self._middleware):
            call_next = self._wrap_middleware(mw, call_next)
        return call_next(tool_name, arguments)

    @staticmethod
    def _wrap_middleware(mw: ToolMiddleware, call_next):
        """One link of the chain (a named helper so the loop closure binds correctly)."""
        return lambda name, args: mw.on_execute_tool(name, args, call_next)

    # -- SupportsToolMiddleware implementation ---------------------------------

    def add_middleware(self, middleware: ToolMiddleware) -> None:
        """Append *middleware* to the chain (innermost, closest to execution)."""
        self._middleware.append(middleware)

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
        schemas = json.loads(self._prompt_strategy.format_tools(self.list_tools()))["tools"]
        return [{"type": "function", "function": s} for s in schemas]
