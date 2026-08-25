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
                "reasoning_options": [{"type": "effort",
                                       "values": ["none", "low", "medium", "high",
                                                  "xhigh", "max"]}],
                "modalities": {"input": ["text", "image", "pdf"], "output": ["text"]},
                "limit": {"context": 1050000, "input": 922000, "output": 128000},
            },
        },
    },
    "zeta-gateway": {
        "id": "zeta-gateway",
        "models": {"gpt-5.6": {"id": "gpt-5.6", "limit": {"context": 1}}},
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

    def test_silence_stays_none_not_false(self):
        info = LiteLLMInfoProvider(_http=CatalogHttp(LITELLM)).describe("llama3")
        assert info.supports_reasoning is None
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
        assert info.input_modalities == ("text", "image", "pdf")
        assert info.output_modalities == ("text",)

    def test_every_carrier_is_listed_the_pick_is_only_labelled(self):
        """One id under many namespaces (measured: 18 for gpt-5.5) and no canonical
        marker -- so meta lists ALL carriers for membership questions ("does openai
        serve this id?"), and "provider" merely names whose near-identical copy
        filled the fields (alphabetically first, an arbitrary choice by design)."""
        info = ModelsDevInfoProvider(_http=CatalogHttp(MODELS_DEV)).describe("gpt-5.6")
        assert info.meta["models_dev"]["providers"] == ["openai", "zeta-gateway"]
        assert info.meta["models_dev"]["provider"] == "openai"

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

    def test_unknown_model_is_a_none_answer(self):
        assert ModelsDevInfoProvider(_http=CatalogHttp(MODELS_DEV)).describe("x") is None
