"""DriverBase -- concrete base for hybrid drivers and orchestrators.

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

from .mcs_driver_interface import MCSDriver, DriverResponse
from .mcs_tool_driver_interface import MCSToolDriver, Tool
from .prompt_strategy import PromptStrategy, UnknownToolBehavior
from .extraction_strategy import (
    ExtractionStrategy,
    TextExtractionStrategy,
    DirectDictExtractionStrategy,
    OpenAIExtractionStrategy,
)
from .mixins.driver_context_mixin import SupportsDriverContext, DriverContext

logger = logging.getLogger(__name__)


class DriverBase(MCSDriver, MCSToolDriver, SupportsDriverContext):
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
            DirectDictExtractionStrategy(),
            OpenAIExtractionStrategy(),
            TextExtractionStrategy(self._strategy),
        ]
        self._preferred_extractor: ExtractionStrategy | None = None

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
        self, llm_response: str | dict, *, streaming: bool = False
    ) -> DriverResponse:
        if isinstance(llm_response, str):
            llm_text = llm_response
        elif isinstance(llm_response, dict):
            llm_text = llm_response.get("content") or json.dumps(llm_response)
        else:
            llm_text = str(llm_response)

        parsed = self._extract(llm_response)
        if parsed is None:
            return DriverResponse()

        tool_name, arguments = parsed

        known = {t.name for t in self.list_tools()}
        if tool_name not in known:
            if self._strategy.unknown_tool_behavior == UnknownToolBehavior.RETRY_WITH_LIST:
                available = ", ".join(sorted(known))
                retry = self._strategy.retry_unknown_tool(tool_name, available)
                return DriverResponse(
                    call_failed=True,
                    call_detail=f"No matching tool '{tool_name}' found.",
                    retry_prompt=retry,
                    messages=[
                        {"role": "assistant", "content": llm_text},
                        {"role": "system", "content": retry},
                    ],
                )
            return DriverResponse()

        logger.info("Executing tool: %s", tool_name)

        try:
            result = self.execute_tool(tool_name, arguments)
            result_text = result if isinstance(result, str) else json.dumps(result)
        except Exception as e:
            retry = self._strategy.retry_execution_failed(tool_name, str(e))
            return DriverResponse(
                call_failed=True,
                call_detail=f"Tool '{tool_name}' failed: {e}",
                retry_prompt=retry,
                messages=[
                    {"role": "assistant", "content": llm_text},
                    {"role": "system", "content": retry},
                ],
            )

        return DriverResponse(
            tool_call_result=result_text,
            call_executed=True,
            messages=[
                {"role": "assistant", "content": llm_text},
                {"role": "system", "content": result_text},
            ],
        )

    # -- SupportsDriverContext override ----------------------------------------

    def get_driver_context(
        self, model_name: str | None = None,
    ) -> DriverContext:
        """Return context for an LLM call.

        When *model_name* is given and the model supports native
        function-calling, the returned :class:`DriverContext` includes
        tool definitions in OpenAI format so the client can pass them
        as ``tools=ctx.tools``.  Otherwise, tools are embedded in
        ``system_message`` as text (the default MCS approach).
        """
        if model_name and self._model_supports_native_tools(model_name):
            return DriverContext(
                system_message=self._custom_system_message or "You are a helpful assistant.",
                tools=self._tools_as_native_dicts(),
            )
        return DriverContext(
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
    ) -> tuple[str, dict[str, Any]] | None:
        """Two-phase extraction: Claim → Extract → Text-Fallback.

        Each strategy can *claim* a response based on its shape (e.g.
        ``"tool_calls"`` key for OpenAI).  The first claimer owns the
        response exclusively -- even when ``extract()`` returns ``None``
        (= "my format, but no tool call").

        ``TextExtractionStrategy`` never claims and serves as the
        natural fallback when no strategy takes ownership.

        The ``_preferred_extractor`` cache promotes the last successful
        claiming strategy to the front of the chain for subsequent
        calls.  This is a stateful optimisation without side-effects:
        the system produces the same result without it, just slower.

        .. note::

           The claim logic relies on the **response shape** (e.g. the
           presence of a ``"tool_calls"`` key) to distinguish native
           tool-call responses from plain text.  This covers >99% of
           practical cases, but edge cases remain -- for instance when
           a native-tool-capable model is called **without** ``tools``
           and produces JSON in ``content`` that resembles a text-based
           tool call.  Future solutions may include passing
           ``model_name`` to ``process_llm_response`` or introducing
           session-level state after ``get_driver_context``.
        """
        ordered = list(self._extractors)
        text_fallback: TextExtractionStrategy | None = None

        if self._preferred_extractor is not None and self._preferred_extractor in ordered:
            ordered = [self._preferred_extractor] + [
                s for s in ordered if s is not self._preferred_extractor
            ]

        for strategy in ordered:
            if isinstance(strategy, TextExtractionStrategy):
                text_fallback = strategy
                continue
            if strategy.claims(llm_response):
                result = strategy.extract(llm_response)
                if result is not None:
                    self._preferred_extractor = strategy
                return result

        if text_fallback is not None:
            return text_fallback.extract(llm_response)
        return None
