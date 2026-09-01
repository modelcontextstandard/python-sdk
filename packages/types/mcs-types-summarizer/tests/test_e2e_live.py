"""End-to-end: the summarizer over a **real** model. Deselected by default:

    pytest packages/types/mcs-types-summarizer -m e2e

Same configuration as the LLM adapter's live tests (defaults: local Ollama, no key):

    MCS_E2E_LLM_BASE_URL     default http://localhost:11434/v1
    MCS_E2E_LLM_MODEL        default qwen3:4b (first entry, if comma-separated)
    MCS_E2E_LLM_KEY          optional
    MCS_E2E_LLM_MAX_TOKENS   wire field name, default "max_tokens"

What only a live run can prove: that a fact buried in the middle of a document
survives chunking, mapping and merging -- and that the truncation trap (a thinking
model spending its whole budget reasoning) is *flagged*, never silent.
"""

from __future__ import annotations

import os

import pytest

from mcs.adapter.llm.completion import CompletionLLMAdapter
from mcs.types.summarizer import LLMSummarizer

pytestmark = pytest.mark.e2e

BASE_URL = os.environ.get("MCS_E2E_LLM_BASE_URL", "http://localhost:11434/v1")
MODEL = os.environ.get("MCS_E2E_LLM_MODEL", "qwen3:4b").split(",")[0].strip()
API_KEY = os.environ.get("MCS_E2E_LLM_KEY")
MAX_TOKENS_FIELD = os.environ.get("MCS_E2E_LLM_MAX_TOKENS", "max_tokens")

#: One fact, buried mid-document between paragraphs that look plausible but say
#: nothing -- so a right answer proves the fact survived chunk, map and merge.
FACT = "Die Kuendigungsfrist des Vertrags betraegt genau drei Monate."
FILLER = ("Der Bericht beschreibt allgemeine organisatorische Ablaeufe und nennt "
          "keine konkreten Fristen oder Zahlen. Er verweist auf interne Prozesse.")
DOCUMENT = "\n\n".join(
    [f"Abschnitt {i}: {FILLER}" for i in range(4)]
    + [f"Abschnitt 4: {FACT}"]
    + [f"Abschnitt {i}: {FILLER}" for i in range(5, 9)]
)
QUERY = "Wie lange ist die Kuendigungsfrist des Vertrags?"


@pytest.fixture(scope="module")
def llm() -> CompletionLLMAdapter:
    return CompletionLLMAdapter(MODEL, base_url=BASE_URL, api_key=API_KEY,
                                max_completion_tokens_field=MAX_TOKENS_FIELD,
                                timeout=300)


def test_small_text_is_stuffed(llm):
    s = LLMSummarizer(llm).summarize(
        "Die Katze heisst Mimi und ist drei Jahre alt.", "Wie heisst die Katze?")
    assert s.strategy == "stuff"
    assert s.chunks == 1
    assert "mimi" in s.text.lower(), f"got {s.text!r}"


def test_a_buried_fact_survives_chunking_and_merging(llm):
    """The whole point of the component: the model never sees the document at once,
    yet the answer contains the one fact that mattered."""
    summarizer = LLMSummarizer(llm, context_window=1280)   # tiny window forces real chunking
    s = summarizer.summarize(DOCUMENT, QUERY)
    assert s.strategy == "map_reduce"
    assert s.chunks >= 2, "the budget was meant to force real chunking"
    assert "drei" in s.text.lower() or "3" in s.text, f"got {s.text!r}"
    assert s.usage.input and s.usage.input > 0           # measured, summed cost


def test_truncation_is_flagged_never_silent(llm):
    """A tight answer budget plus a thinking model can yield an empty answer with no
    error anywhere -- measured on qwen3. The flag is the only trace; assert the link
    in both directions rather than assuming which way this model falls."""
    s = LLMSummarizer(llm, max_answer_tokens=24).summarize(
        "Die Katze heisst Mimi.", "Wie heisst die Katze?")
    if not s.text.strip():
        assert s.truncated, (
            "empty answer without the truncated flag: 'nothing relevant' and "
            "'budget swallowed by reasoning' would be indistinguishable"
        )
    else:
        assert s.usage.output is None or s.usage.output <= 24 + 8
