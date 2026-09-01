"""End-to-end against a **real** endpoint. Deselected by default -- run deliberately:

    pytest packages/adapters/mcs-adapter-llm -m e2e

Deselected rather than skipped, on purpose. A skipped test reports as a harmless dot in
the summary and quietly stops guarding anything; a deselected one is counted and named.

Configuration (defaults point at a local Ollama, so no key and no cloud bill):

    MCS_E2E_LLM_BASE_URL     default http://localhost:11434/v1
    MCS_E2E_LLM_MODEL        default qwen3:4b -- comma-separated to run several
    MCS_E2E_LLM_KEY          optional; set it to run against OpenAI or a gateway
    MCS_E2E_LLM_MAX_TOKENS   wire field name, default "max_tokens"; OpenAI's
                             reasoning models require "max_completion_tokens"

Against OpenAI, for instance:

    MCS_E2E_LLM_BASE_URL=https://api.openai.com/v1 \
    MCS_E2E_LLM_MODEL=gpt-5.5,gpt-5.6 \
    MCS_E2E_LLM_MAX_TOKENS=max_completion_tokens \
    MCS_E2E_LLM_KEY=$OPENAI_API_KEY pytest ... -m e2e

What this proves that the offline suite cannot: that a real backend's response actually
fits the shape we assume. Every finding in this package's README came from running these,
not from reading a specification -- that a thinking model can spend an entire answer
budget on reasoning and return an empty string with no error, and that OpenAI's reasoning
models reject ``max_tokens`` by name.

**No temperature is set.** Pinning it to 0 for reproducibility works on local servers and
fails on GPT-5 (*"'temperature' does not support 0 with this model"*), so the tests are
written to tolerate sampling instead of forbidding it.
"""

from __future__ import annotations

import os

import pytest

from mcs.adapter.llm.completion import CompletionLLMAdapter
from mcs.types.llm import LLMResponse, ModelInfo

pytestmark = pytest.mark.e2e

BASE_URL = os.environ.get("MCS_E2E_LLM_BASE_URL", "http://localhost:11434/v1")
MODELS = [m.strip() for m in os.environ.get("MCS_E2E_LLM_MODEL", "qwen3:4b").split(",") if m.strip()]
API_KEY = os.environ.get("MCS_E2E_LLM_KEY")
MAX_TOKENS_FIELD = os.environ.get("MCS_E2E_LLM_MAX_TOKENS", "max_tokens")

#: Short, and answerable from the text alone -- so a wrong answer means the plumbing is
#: wrong, not that the model was asked something hard.
TEXT = "Die Katze heisst Mimi und ist drei Jahre alt."
QUESTION = f"Text: {TEXT}\n\nFrage: Wie heisst die Katze? Antworte mit einem Wort."
STEERING = "Answer only from the text below. Be terse."


@pytest.fixture(scope="module", params=MODELS)
def llm(request) -> CompletionLLMAdapter:
    return CompletionLLMAdapter(request.param, base_url=BASE_URL, api_key=API_KEY,
                                max_completion_tokens_field=MAX_TOKENS_FIELD, timeout=300)


def test_answers_from_the_text(llm):
    """The whole contract in one call: text out, and it is the right text."""
    answer = llm.complete(QUESTION, system=STEERING, max_completion_tokens=2000)
    assert isinstance(answer, LLMResponse)
    assert "mimi" in answer.text.lower(), f"got {answer.text!r}"
    assert answer.truncated is False


def test_the_backend_measures_what_we_would_have_guessed(llm):
    """`usage` is the reason `LLMResponse` exists: real counts from the model's own
    tokenizer, free with every call. A caller that compares them against
    ``estimate_tokens`` stops guessing after the first round."""
    answer = llm.complete(QUESTION, system=STEERING, max_completion_tokens=2000)
    assert answer.usage.input and answer.usage.input > 0
    assert answer.usage.output and answer.usage.output > 0
    assert answer.model, "a backend should say which model answered"


def test_a_thinking_model_can_swallow_the_whole_answer_budget(llm):
    """The finding that justifies `truncated`.

    Ask a reasoning model for an answer with a modest budget and the *thinking* can
    consume all of it: ``content`` comes back as an empty string, ``finish_reason`` is
    ``"length"``, and no error is raised anywhere. A summarizer that only looked at the
    text would silently produce nothing.

    Written to hold either way -- a non-reasoning model simply answers within the budget
    -- because what must be guaranteed is the *link*: empty text is never silent.
    """
    answer = llm.complete(QUESTION, system=STEERING, max_completion_tokens=48)
    if answer.text.strip():
        assert answer.usage.output and answer.usage.output <= 48 + 8
    else:
        assert answer.truncated, (
            "an empty answer must be explained by finish_reason='length'; otherwise a "
            "caller has no way to tell 'nothing to say' from 'budget spent thinking'"
        )


def test_describe_relays_what_the_endpoint_states(llm):
    """Against Ollama the inquiry is rich (capabilities + architecture context
    length); against OpenAI it yields None -- the models route does not even resolve
    alias ids. Both are correct answers; neither may crash."""
    stated = llm.describe()
    if "11434" in BASE_URL:
        assert isinstance(stated, ModelInfo)
        assert stated.context_window and stated.context_window > 0
        assert stated.supports_function_calling is not None
        # A served completion model always states at least text in; a multimodal
        # one (gemma4:e4b) adds image/audio -- either way the field is stated.
        assert stated.input_modalities and "text" in stated.input_modalities
    else:
        assert stated is None or isinstance(stated, ModelInfo)
