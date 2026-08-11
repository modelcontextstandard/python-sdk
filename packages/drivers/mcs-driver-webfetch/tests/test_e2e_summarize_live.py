"""End-to-end: fetch a real page, condense it with a real model. Deselected by default:

    pytest packages/drivers/mcs-driver-webfetch -m e2e

The full pipeline in one call -- HTTP fetch, extraction strategies, chunking,
summarization -- against a page whose content is stable by design (example.com exists
for exactly this). Same environment variables as every other live test:

    MCS_E2E_LLM_BASE_URL     default http://localhost:11434/v1
    MCS_E2E_LLM_MODEL        default qwen3:4b (first entry, if comma-separated)
    MCS_E2E_LLM_KEY          optional
    MCS_E2E_LLM_MAX_TOKENS   wire field name, default "max_tokens"
"""

from __future__ import annotations

import os

import pytest

from mcs.adapter.llm.completion import CompletionLLMAdapter
from mcs.driver.webfetch import WebfetchToolDriver
from mcs.types.summarizer import LLMSummarizer

pytestmark = pytest.mark.e2e

BASE_URL = os.environ.get("MCS_E2E_LLM_BASE_URL", "http://localhost:11434/v1")
MODEL = os.environ.get("MCS_E2E_LLM_MODEL", "qwen3:4b").split(",")[0].strip()
API_KEY = os.environ.get("MCS_E2E_LLM_KEY")
MAX_TOKENS_FIELD = os.environ.get("MCS_E2E_LLM_MAX_TOKENS", "max_tokens")


def test_fetch_page_answers_a_question_about_a_real_page():
    llm = CompletionLLMAdapter(MODEL, base_url=BASE_URL, api_key=API_KEY,
                               max_completion_tokens_field=MAX_TOKENS_FIELD,
                               timeout=300)
    driver = WebfetchToolDriver(summarizer=LLMSummarizer(llm))
    result = driver.execute_tool("fetch_page", {
        "url": "https://example.com",
        "prompt": "What is this domain used for? Answer in one sentence.",
    })
    assert result["content"].strip(), f"empty answer: {result!r}"
    assert "example" in result["content"].lower() or "illustrat" in result["content"].lower(), (
        f"answer does not reflect the page: {result['content']!r}")
    assert result["source_chars"] > 0
    assert result["summary_strategy"] in ("stuff", "map_reduce", "refine")
