"""Model knowledge from models.dev.

A purpose-built open database (by the opencode/SST maintainers; measured: ~200
providers, ~7300 models), organised provider-first, and the more deliberate schema:
explicit ``limit.context`` / ``limit.output``, ``modalities.input`` / ``.output``,
``reasoning``, ``tool_call`` -- plus statements no other source measured here makes,
such as ``temperature: false`` on models that reject the parameter and the accepted
``reasoning_options`` effort values.
"""

from __future__ import annotations

from typing import Any

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
    names the namespace whose entry populated the fields: the **fullest** one (most
    fields stated; alphabetical on ties). A data rule, not a canonical-provider
    guess -- measured, gateway copies drop statements the first-party entry makes
    (abacus lists ``reasoning_options: []`` for gpt-5.5 where openai names the five
    accepted values). Pass *provider* to pin the namespace outright.

    Ids come in a **qualified** form too, and it matters: deployment facts differ
    per namespace (measured: 401 ids state different context windows across their
    carriers -- the open-weight ``openai/gpt-oss-120b`` spans 65 536 to 131 072
    over 29 providers), so which number applies is only answerable *with* the
    namespace. Resolution is a plain **tree walk with a literal fallback**:

    1. A bare name is a model id -- the first provider carrying it wins.
    2. With a ``/``: segment one as the namespace, the rest as its *exact* id
       (``openrouter/moonshotai/kimi-k3`` -> the ``openrouter`` namespace's
       vendor-qualified id ``moonshotai/kimi-k3``). A hit means exactly that
       provider.
    3. No walk hit: the **whole** input as a literal id, first provider carrying
       it wins (``moonshotai/kimi-k3`` when no ``moonshotai`` namespace exists,
       but gateways carry that literal id).
    4. Nothing did: ``None`` -- ``openrouter/moonshot-ai/kimi-k3`` is dead because
       openrouter does not carry ``moonshot-ai/kimi-k3`` and nobody carries the
       whole string. Never a re-reading of segments beyond that.

    Knowledge stays planning input either way: the endpoint's statement and the
    overflow learning outrank it.
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
        carriers: dict[str, dict[str, Any]] = {}
        if "/" in model and not self.provider:
            # Tree walk: segment one as the namespace, the rest as its exact id.
            # A hit means exactly that provider.
            namespace, _, bare = model.partition("/")
            namespace_entry = data.get(namespace)
            if isinstance(namespace_entry, dict):
                candidate = (namespace_entry.get("models") or {}).get(bare)
                if isinstance(candidate, dict):
                    carriers[namespace] = candidate
        if not carriers:
            # The WHOLE input as a literal id, wherever it is carried. For a bare
            # name this is the scan; for a slashed one the second class -- and
            # never a re-reading of segments: a walk miss plus a literal miss is
            # None, not some other split's answer.
            for namespace_id, namespace_entry in namespaces:
                if not isinstance(namespace_entry, dict) or not namespace_id:
                    continue
                candidate = (namespace_entry.get("models") or {}).get(model)
                if isinstance(candidate, dict):
                    carriers[namespace_id] = candidate
        if not carriers:
            return None
        provider_id = max(sorted(carriers), key=lambda pid: len(carriers[pid]))
        entry = carriers[provider_id]
        raw_limit = entry.get("limit")
        limit: dict[str, Any] = raw_limit if isinstance(raw_limit, dict) else {}
        raw_modalities = entry.get("modalities")
        modalities: dict[str, Any] = (raw_modalities
                                      if isinstance(raw_modalities, dict) else {})
        return ModelInfo(
            context_window=limit.get("context")
            if isinstance(limit.get("context"), int) else None,
            max_output_tokens=limit.get("output")
            if isinstance(limit.get("output"), int) else None,
            supports_function_calling=entry.get("tool_call")
            if isinstance(entry.get("tool_call"), bool) else None,
            supports_reasoning=entry.get("reasoning")
            if isinstance(entry.get("reasoning"), bool) else None,
            supports_temperature=entry.get("temperature")
            if isinstance(entry.get("temperature"), bool) else None,
            input_modalities=self._modalities(modalities.get("input")),
            output_modalities=self._modalities(modalities.get("output")),
            # Bookkeeping keys LAST so they cannot be shadowed: some entries carry
            # a "provider" field of their own (measured: a gateway's serving info,
            # a dict) -- ours are the documented semantics and the adapter's
            # membership rule reads "providers", so ours win the collision.
            meta={"models_dev": {**entry, "provider": provider_id,
                                 "providers": sorted(carriers)}},
        )
