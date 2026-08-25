"""Catalogue providers: knowledge lookup over an injected transport, None on failure.

Fixture payloads are trimmed copies of the measured real shapes (LiteLLM's JSON,
models.dev's api.json) -- the mapping tests pin the field semantics we rely on.
"""

from __future__ import annotations

import json

from mcs.adapter.llm.info import LiteLLMInfoProvider, ModelsDevInfoProvider
from mcs.types.http import HttpResponse
from mcs.types.llm import ModelInfoProvider


class CatalogHttp:
    """Replays one canned catalogue document; counts the fetches."""

    def __init__(self, payload: object, status: int = 200) -> None:
        self.payload = payload
        self.status = status
        self.calls: list[dict] = []

    def request(self, method, url, *, params=None, json_body=None, headers=None,
                timeout=None):
        self.calls.append({"method": method, "url": url, "headers": headers})
        text = self.payload if isinstance(self.payload, str) else json.dumps(self.payload)
        return HttpResponse(status_code=self.status, text=text)


#: Trimmed from the real file: flat id map, prices beside capabilities, and the two id
#: spellings ("gpt-5" plain, "ollama/llama3" provider-prefixed).
LITELLM = {
    "gpt-5": {
        "litellm_provider": "openai", "mode": "chat",
        "max_input_tokens": 272000, "max_output_tokens": 128000, "max_tokens": 128000,
        "input_cost_per_token": 1.25e-06, "output_cost_per_token": 1e-05,
        "supports_function_calling": True, "supports_reasoning": True,
        "supported_modalities": ["text", "image"],
        "supported_output_modalities": ["text"],
    },
    "ollama/llama3": {
        "litellm_provider": "ollama", "mode": "chat",
        "max_input_tokens": 8192, "max_output_tokens": 8192,
        "supports_function_calling": True,
    },
    # Measured: Bedrock cross-region profiles keep their backend-native dotted id.
    "us.openai.gpt-5.6-luna": {
        "litellm_provider": "bedrock_converse", "mode": "chat",
        "max_input_tokens": 200000,
    },
    "sample_spec": {"mode": "chat"},
}

#: Trimmed from the real api.json: provider-first, limit/modalities as objects, and the
#: statements no other source makes (temperature: false, reasoning_options).
MODELS_DEV = {
    "openai": {
        "id": "openai", "npm": "@ai-sdk/openai",
        "models": {
            "gpt-5.6": {
                "id": "gpt-5.6", "reasoning": True, "tool_call": True,
                "temperature": False,
                # Measured: some entries carry their own "provider" field (a dict
                # of serving info) -- it must never shadow the bookkeeping keys.
                "provider": {"npm": "@ai-sdk/openai-compatible"},
                "reasoning_options": [{"type": "effort",
                                       "values": ["none", "low", "medium", "high",
                                                  "xhigh", "max"]}],
                "modalities": {"input": ["text", "image", "pdf"], "output": ["text"]},
                "limit": {"context": 1050000, "input": 922000, "output": 128000},
            },
        },
    },
    "aaa-gateway": {
        "id": "aaa-gateway",
        "models": {"gpt-5.6": {"id": "gpt-5.6", "limit": {"context": 2}}},
    },
    "zeta-gateway": {
        "id": "zeta-gateway",
        "models": {"gpt-5.6": {"id": "gpt-5.6", "limit": {"context": 1}},
                   "openai/gpt-5.6": {"id": "openai/gpt-5.6",
                                      "limit": {"context": 7}},
                   "vendorx/model-y": {"id": "vendorx/model-y",
                                       "limit": {"context": 9}}},
    },
}


class TestLiteLLM:
    def test_satisfies_the_provider_contract(self):
        assert isinstance(LiteLLMInfoProvider(_http=CatalogHttp({})), ModelInfoProvider)

    def test_maps_the_measured_field_semantics(self):
        """max_input_tokens IS the window (max_tokens is a legacy output alias)."""
        info = LiteLLMInfoProvider(_http=CatalogHttp(LITELLM)).describe("gpt-5")
        assert info.context_window == 272000
        assert info.max_output_tokens == 128000
        assert info.supports_function_calling is True
        assert info.supports_reasoning is True
        assert info.input_modalities == ("text", "image")
        assert info.output_modalities == ("text",)

    def test_prices_survive_in_meta_for_a_future_cost_tracker(self):
        info = LiteLLMInfoProvider(_http=CatalogHttp(LITELLM)).describe("gpt-5")
        assert info.meta["litellm"]["input_cost_per_token"] == 1.25e-06

    def test_provider_prefixed_ids_are_found_by_plain_name(self):
        """The file mixes spellings; a client says "llama3", not "ollama/llama3"."""
        info = LiteLLMInfoProvider(_http=CatalogHttp(LITELLM)).describe("llama3")
        assert info.context_window == 8192
        assert info.meta["litellm"]["resolved_id"] == "ollama/llama3"

    def test_bedrock_dotted_ids_are_found_by_plain_name(self):
        """Bedrock profiles keep their native dotted id (measured: all 122 dotted
        keys are bedrock) -- the third lookup stage reaches them."""
        info = LiteLLMInfoProvider(_http=CatalogHttp(LITELLM)).describe("gpt-5.6-luna")
        assert info.context_window == 200000
        assert info.meta["litellm"]["resolved_id"] == "us.openai.gpt-5.6-luna"

    def test_silence_stays_none_not_false(self):
        """LiteLLM's JSON has no temperature statement at all -- None, never False,
        so a consumer's stated-False gate never fires on this catalogue."""
        info = LiteLLMInfoProvider(_http=CatalogHttp(LITELLM)).describe("llama3")
        assert info.supports_reasoning is None
        assert info.supports_temperature is None
        assert info.input_modalities is None

    def test_unknown_model_is_a_none_answer(self):
        assert LiteLLMInfoProvider(_http=CatalogHttp(LITELLM)).describe("nope") is None

    def test_one_fetch_serves_every_lookup(self):
        """A catalogue is megabytes; per-run describe() must not mean per-run fetch."""
        http = CatalogHttp(LITELLM)
        provider = LiteLLMInfoProvider(_http=http)
        provider.describe("gpt-5")
        provider.describe("llama3")
        assert len(http.calls) == 1

    def test_transport_failure_never_raises_and_is_not_hammered(self):
        class BoomHttp:
            def __init__(self):
                self.calls = 0

            def request(self, *a, **k):
                self.calls += 1
                raise OSError("network down")

        http = BoomHttp()
        provider = LiteLLMInfoProvider(_http=http)
        assert provider.describe("gpt-5") is None
        assert provider.describe("gpt-5") is None
        assert http.calls == 1


class TestModelsDev:
    def test_maps_the_measured_field_semantics(self):
        """limit.context is the total window -- the deliberate schema."""
        info = ModelsDevInfoProvider(_http=CatalogHttp(MODELS_DEV)).describe("gpt-5.6")
        assert info.context_window == 1050000
        assert info.max_output_tokens == 128000
        assert info.supports_function_calling is True
        assert info.supports_reasoning is True
        assert info.supports_temperature is False   # the statement nobody else makes
        assert info.input_modalities == ("text", "image", "pdf")
        assert info.output_modalities == ("text",)

    def test_every_carrier_is_listed_the_fullest_fills_the_fields(self):
        """One id under many namespaces (measured: 18 for gpt-5.5) and no canonical
        marker -- so meta lists ALL carriers for membership questions ("does openai
        serve this id?"), and the FULLEST entry fills the fields: gateway copies
        drop statements (measured: abacus lists reasoning_options: [] where openai
        names five values), so most-fields-stated wins over alphabetical order."""
        info = ModelsDevInfoProvider(_http=CatalogHttp(MODELS_DEV)).describe("gpt-5.6")
        assert info.meta["models_dev"]["providers"] == [
            "aaa-gateway", "openai", "zeta-gateway"]
        # The entry's own "provider" dict (serving info) must not shadow ours.
        assert info.meta["models_dev"]["provider"] == "openai"
        assert info.context_window == 1050000       # not aaa-gateway's 2

    def test_a_provider_hint_pins_the_namespace(self):
        info = ModelsDevInfoProvider(
            _http=CatalogHttp(MODELS_DEV), provider="zeta-gateway").describe("gpt-5.6")
        assert info.context_window == 1
        assert info.meta["models_dev"]["provider"] == "zeta-gateway"
        assert info.meta["models_dev"]["providers"] == ["zeta-gateway"]

    def test_the_statements_nobody_else_makes_survive_in_meta(self):
        """temperature: false and the accepted effort values -- models.dev exclusives."""
        info = ModelsDevInfoProvider(_http=CatalogHttp(MODELS_DEV)).describe("gpt-5.6")
        assert info.meta["models_dev"]["temperature"] is False
        assert "xhigh" in info.meta["models_dev"]["reasoning_options"][0]["values"]

    def test_a_user_agent_travels(self):
        """Measured: models.dev answers 403 to a client without a User-Agent."""
        http = CatalogHttp(MODELS_DEV)
        ModelsDevInfoProvider(_http=http).describe("gpt-5.6")
        assert http.calls[0]["headers"]["User-Agent"]

    def test_a_qualified_id_addresses_its_namespace_first(self):
        """namespace/id pins per call -- deployment facts differ per namespace, so
        'which model is meant' is only answerable WITH the namespace. The openai
        namespace carries gpt-5.6, so the addressing wins even though a gateway
        also lists the literal id "openai/gpt-5.6"."""
        info = ModelsDevInfoProvider(
            _http=CatalogHttp(MODELS_DEV)).describe("openai/gpt-5.6")
        assert info.context_window == 1050000    # openai's entry, not zeta's literal
        assert info.meta["models_dev"]["providers"] == ["openai"]

    def test_a_walk_miss_falls_back_to_the_literal_id(self):
        """'vendorx' is no namespace, but zeta-gateway carries the literal id
        'vendorx/model-y' -- the second class answers."""
        info = ModelsDevInfoProvider(
            _http=CatalogHttp(MODELS_DEV)).describe("vendorx/model-y")
        assert info.context_window == 9
        assert info.meta["models_dev"]["providers"] == ["zeta-gateway"]

    def test_the_walk_reaches_a_gateways_vendor_qualified_id(self):
        """Tree walk, one level: zeta-gateway's exact id 'vendorx/model-y'."""
        info = ModelsDevInfoProvider(
            _http=CatalogHttp(MODELS_DEV)).describe("zeta-gateway/vendorx/model-y")
        assert info.context_window == 9
        assert info.meta["models_dev"]["providers"] == ["zeta-gateway"]

    def test_walk_miss_plus_literal_miss_is_none_never_a_reread(self):
        """The live case this pins: 'openrouter/moonshot-ai/kimi-k3' is dead when
        openrouter does not carry the rest and nobody carries the whole string.
        Segments are never re-read into some other split's answer."""
        assert ModelsDevInfoProvider(
            _http=CatalogHttp(MODELS_DEV)).describe("foo/openai/gpt-5.6") is None

    def test_unknown_model_is_a_none_answer(self):
        assert ModelsDevInfoProvider(_http=CatalogHttp(MODELS_DEV)).describe("x") is None
