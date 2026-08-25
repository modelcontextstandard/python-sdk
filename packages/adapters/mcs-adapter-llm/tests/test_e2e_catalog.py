"""Live catalogue lookups -- prove the real documents still have the measured shape.

Needs the internet, nothing else: no key, no model server. Deselected by default like
every e2e test; run with ``pytest packages/adapters/mcs-adapter-llm -m e2e``.
"""

from __future__ import annotations

import pytest

from mcs.adapter.llm.info import LiteLLMInfoProvider, ModelsDevInfoProvider

pytestmark = pytest.mark.e2e


def test_litellm_catalog_still_speaks_the_mapped_schema():
    info = LiteLLMInfoProvider().describe("gpt-5")
    assert info is not None, "gpt-5 vanished from LiteLLM's JSON -- check the URL/schema"
    assert info.context_window and info.context_window > 100000
    assert info.supports_reasoning is True
    assert info.meta["litellm"]["litellm_provider"] == "openai"


def test_models_dev_still_speaks_the_mapped_schema():
    info = ModelsDevInfoProvider(provider="openai").describe("gpt-5")
    assert info is not None, "openai/gpt-5 vanished from models.dev -- check the schema"
    assert info.context_window and info.context_window > 100000
    assert info.supports_function_calling is True
    assert info.input_modalities and "text" in info.input_modalities
    # The statement nobody else makes -- the reason this catalogue earns its keep.
    assert info.supports_temperature is False
