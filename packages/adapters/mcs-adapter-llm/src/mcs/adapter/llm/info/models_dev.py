"""Model knowledge from models.dev.

A purpose-built open database (by the opencode/SST maintainers; measured: ~200
providers, ~7300 models), organised provider-first, and the more deliberate schema:
explicit ``limit.context`` / ``limit.output``, ``modalities.input`` / ``.output``,
``reasoning``, ``tool_call`` -- plus statements no other source measured here makes,
such as ``temperature: false`` on models that reject the parameter and the accepted
``reasoning_options`` effort values.
"""

from __future__ import annotations

from mcs.types.llm import ModelInfo

from .catalog import ModelInfoCatalog

#: The models.dev API -- the whole database in one JSON document.
DEFAULT_MODELS_DEV_URL = "https://models.dev/api.json"


class ModelsDevInfoProvider(ModelInfoCatalog):
    """:class:`~mcs.types.llm.ModelInfoProvider` over the models.dev database.

    The database is provider-first (``{"openai": {"models": {...}}, ...}``), and one
    model id may appear under **many** namespaces -- measured, ``gpt-5.5`` sits under
    18: the first-party provider plus every gateway that resells it, with no field
    marking which copy is canonical. So this provider does not pretend to know:
    ``meta["models_dev"]["providers"]`` lists *every* namespace carrying the id --
    the honest answer, and the one a consumer's question actually needs ("does
    ``openai`` serve this id?" is a membership check, not a pick). ``"provider"``
    names the namespace whose entry populated the fields: the alphabetically first,
    an arbitrary choice among near-identical copies and labelled as such rather than
    dressed up as canonical. Pass *provider* to pin the namespace outright.
    """

    def __init__(self, url: str = DEFAULT_MODELS_DEV_URL, *,
                 provider: str | None = None, timeout: int = 60, _http=None) -> None:
        super().__init__(url, timeout=timeout, _http=_http)
        self.provider = provider

    def describe(self, model: str) -> ModelInfo | None:
        data = self._load()
        if not data:
            return None
        namespaces = ([(self.provider, data.get(self.provider))]
                      if self.provider else sorted(data.items()))
        carriers = {provider_id: (provider_entry.get("models") or {}).get(model)
                    for provider_id, provider_entry in namespaces
                    if isinstance(provider_entry, dict)
                    and isinstance((provider_entry.get("models") or {}).get(model), dict)}
        if not carriers:
            return None
        provider_id, entry = next(iter(carriers.items()))
        limit = entry.get("limit") if isinstance(entry.get("limit"), dict) else {}
        modalities = (entry.get("modalities")
                      if isinstance(entry.get("modalities"), dict) else {})
        return ModelInfo(
            context_window=limit.get("context")
            if isinstance(limit.get("context"), int) else None,
            max_output_tokens=limit.get("output")
            if isinstance(limit.get("output"), int) else None,
            supports_function_calling=entry.get("tool_call")
            if isinstance(entry.get("tool_call"), bool) else None,
            supports_reasoning=entry.get("reasoning")
            if isinstance(entry.get("reasoning"), bool) else None,
            input_modalities=self._modalities(modalities.get("input")),
            output_modalities=self._modalities(modalities.get("output")),
            meta={"models_dev": {"provider": provider_id,
                                 "providers": sorted(carriers), **entry}},
        )
