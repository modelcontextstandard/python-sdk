"""Model knowledge from LiteLLM's community JSON.

The by-product of the LiteLLM proxy and the most complete database around (measured:
~3200 entries, ~1.4 MB), organised as a flat id map that mixes two spellings --
``"gpt-5"`` plain, ``"ollama/llama3"`` provider-prefixed. Rich on prices and
``supports_*`` flags; MIT-licensed, community-maintained, updated with practically
every LiteLLM release.
"""

from __future__ import annotations

from mcs.types.llm import ModelInfo

from .catalog import ModelInfoCatalog

#: Raw GitHub view of the file the LiteLLM proxy itself reads.
DEFAULT_LITELLM_URL = (
    "https://raw.githubusercontent.com/BerriAI/litellm/main/"
    "model_prices_and_context_window.json"
)


class LiteLLMInfoProvider(ModelInfoCatalog):
    """:class:`~mcs.types.llm.ModelInfoProvider` over LiteLLM's JSON.

    Lookup is the exact id first, then any ``provider/id``-prefixed entry (a client
    says ``"llama3"``, the file says ``"ollama/llama3"``). The raw entry rides in
    ``meta["litellm"]`` -- including the price fields this maps nowhere yet, so a cost
    tracker finds them the day it exists.

    Note the file's field semantics: ``max_input_tokens`` is the input window and
    ``max_tokens`` is a legacy alias for the *output* limit. ``context_window`` is
    therefore mapped from ``max_input_tokens`` -- slightly conservative next to a
    total-window statement, which is the safe direction to be wrong in.
    """

    def __init__(self, url: str = DEFAULT_LITELLM_URL, *, timeout: int = 60,
                 _http=None) -> None:
        super().__init__(url, timeout=timeout, _http=_http)

    def describe(self, model: str) -> ModelInfo | None:
        data = self._load()
        if not data:
            return None
        resolved, entry = model, data.get(model)
        if not isinstance(entry, dict):
            suffix = f"/{model}"
            resolved, entry = next(
                ((key, value) for key, value in sorted(data.items())
                 if key.endswith(suffix) and isinstance(value, dict)),
                (model, None),
            )
        if not isinstance(entry, dict):
            return None
        return ModelInfo(
            context_window=entry.get("max_input_tokens")
            if isinstance(entry.get("max_input_tokens"), int) else None,
            max_output_tokens=entry.get("max_output_tokens")
            if isinstance(entry.get("max_output_tokens"), int) else None,
            supports_function_calling=entry.get("supports_function_calling")
            if isinstance(entry.get("supports_function_calling"), bool) else None,
            supports_reasoning=entry.get("supports_reasoning")
            if isinstance(entry.get("supports_reasoning"), bool) else None,
            input_modalities=self._modalities(entry.get("supported_modalities")),
            output_modalities=self._modalities(entry.get("supported_output_modalities")),
            meta={"litellm": {"resolved_id": resolved, **entry}},
        )
