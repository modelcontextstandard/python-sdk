"""LLMSummarizer against a scripted fake -- no model, no network, deterministic.

The fake speaks the port's portable core and recognises the summarizer's prompts by
their fixed phrases, which doubles as a check that those phrases exist: if a template
loses its marker, the fake answers wrongly and the assertions catch it.
"""

from __future__ import annotations

import pytest

from mcs.types.llm import (
    ContextWindowExceeded,
    LLMPort,
    LLMResponse,
    TokenUsage,
    estimate_tokens,
)
from mcs.types.summarizer import NO_CONTENT, LLMSummarizer, Summary, SummarizerPort


class FakeLLM:
    """Deterministic LLMPort: answers by prompt kind, records calls, optional window."""

    def __init__(self, window_tokens=None, map_answer="PART", final_answer="FINAL",
                 truncate_calls=()):
        self.calls: list[str] = []
        self.window = window_tokens
        self.map_answer = map_answer
        self.final_answer = final_answer
        self.truncate = set(truncate_calls)

    def complete(self, prompt, *, system=None, max_completion_tokens=None, **kwargs):
        n = len(self.calls)
        self.calls.append(prompt)
        if self.window is not None and estimate_tokens(prompt) > self.window:
            raise ContextWindowExceeded(limit=self.window)
        if "one part of a larger document" in prompt:          # map
            text = self.map_answer(prompt) if callable(self.map_answer) else self.map_answer
        else:                                                  # stuff / merge / refine
            text = self.final_answer
        return LLMResponse(
            text=text,
            usage=TokenUsage(prompt=11, completion=7),
            finish_reason="length" if n in self.truncate else "stop",
        )

    @property
    def map_calls(self):
        return [p for p in self.calls if "one part of a larger document" in p]

    @property
    def merge_calls(self):
        return [p for p in self.calls if "Partial answers" in p]


#: ~19k characters over 30 paragraphs -- far beyond the default 3000-token budget.
BIG = "\n\n".join(
    f"Absatz {i}: " + "Inhalt ohne besondere Bedeutung fuer die Frage. " * 15
    for i in range(30)
)
SMALL = "Die Katze heisst Mimi und ist drei Jahre alt."
QUERY = "Wie heisst die Katze?"


class TestContract:

    def test_satisfies_the_port(self):
        assert isinstance(LLMSummarizer(FakeLLM()), SummarizerPort)

    def test_the_fake_satisfies_the_llm_port(self):
        """The summarizer must run on anything that speaks the portable core."""
        assert isinstance(FakeLLM(), LLMPort)

    def test_empty_text_raises(self):
        with pytest.raises(ValueError, match="text is empty"):
            LLMSummarizer(FakeLLM()).summarize("   ", QUERY)

    def test_empty_query_raises(self):
        """The query is the definition of the task, not an option."""
        with pytest.raises(ValueError, match="query is empty"):
            LLMSummarizer(FakeLLM()).summarize(SMALL, "")

    def test_unknown_strategy_raises(self):
        with pytest.raises(ValueError, match="strategy"):
            LLMSummarizer(FakeLLM(), strategy="tree_of_thought")

    def test_concurrency_must_be_positive(self):
        with pytest.raises(ValueError, match="concurrency"):
            LLMSummarizer(FakeLLM(), concurrency=0)


class TestStuff:

    def test_small_text_is_one_call(self):
        llm = FakeLLM()
        s = LLMSummarizer(llm).summarize(SMALL, QUERY)
        assert isinstance(s, Summary)
        assert s.strategy == "stuff"
        assert s.chunks == 1
        assert s.text == "FINAL"
        assert len(llm.calls) == 1

    def test_query_travels_on_the_result(self):
        """A stored summary without its query is prose of unknown intent."""
        s = LLMSummarizer(FakeLLM()).summarize(SMALL, QUERY)
        assert s.query == QUERY


class TestMapReduce:

    def test_big_text_maps_then_merges(self):
        llm = FakeLLM()
        s = LLMSummarizer(llm).summarize(BIG, QUERY)
        assert s.strategy == "map_reduce"      # auto promoted: the estimate said so
        assert s.chunks > 1
        assert s.chunks == len(llm.map_calls)  # chunks = leaves actually read
        assert llm.merge_calls                 # a merge happened
        assert s.text == "FINAL"               # ...and its answer is the result

    def test_nothing_relevant_yields_an_empty_answer_without_a_merge(self):
        """All-sentinel maps mean the document holds nothing on the query. That is an
        answer -- and paying for a merge of nothing would be absurd."""
        llm = FakeLLM(map_answer=NO_CONTENT)
        s = LLMSummarizer(llm).summarize(BIG, QUERY)
        assert s.text == ""
        assert s.truncated is False            # empty is NOT the same as cut off
        assert not llm.merge_calls

    def test_a_single_relevant_chunk_skips_the_merge(self):
        llm = FakeLLM(map_answer=lambda p: "TREFFER" if "Absatz 7:" in p else NO_CONTENT)
        s = LLMSummarizer(llm).summarize(BIG, QUERY)
        assert s.text == "TREFFER"
        assert not llm.merge_calls

    def test_usage_is_summed_over_every_call(self):
        llm = FakeLLM()
        s = LLMSummarizer(llm).summarize(BIG, QUERY)
        assert s.usage.prompt == 11 * len(llm.calls)
        assert s.usage.completion == 7 * len(llm.calls)
        assert s.usage.reasoning is None       # never reported -> stays None, not 0


class TestOverflowLearning:

    def test_pinned_stuff_fails_rather_than_mutating(self):
        """The caller asked for exactly one call over the whole text. If that cannot
        be, failing IS the answer -- a pinned strategy never silently becomes another."""
        with pytest.raises(ContextWindowExceeded):
            LLMSummarizer(FakeLLM(window_tokens=50), strategy="stuff").summarize(
                SMALL * 20, QUERY)

    def test_auto_falls_back_and_learns_from_the_backend(self):
        """The estimate said stuff fits; the backend disagreed. auto falls back to
        map_reduce, and the named limit shrinks the working budget -- the same
        summarizer never hits the same wall twice."""
        llm = FakeLLM(window_tokens=400)
        summarizer = LLMSummarizer(llm, chunk_tokens=100_000)   # estimate: everything fits
        s = summarizer.summarize(BIG, QUERY)
        assert s.strategy == "map_reduce"
        assert s.chunks > 1
        # limit // 2 == 200, lifted to the floor below which template + query would
        # dominate the call: max(256, 200).
        assert summarizer._chunk_tokens == 256

    def test_an_overflowing_map_chunk_is_split_until_it_fits(self):
        """Every leaf gets read: an overflow re-splits that chunk instead of dropping
        it, so no part of the document silently vanishes from the answer."""
        llm = FakeLLM(window_tokens=1500)
        s = LLMSummarizer(llm).summarize(BIG, QUERY)            # default 3000 > window
        assert s.text == "FINAL"
        # The fake records *attempts*: oversized prompts that overflowed and were then
        # split are in map_calls too. Summary.chunks counts what was actually read.
        fitting = [p for p in llm.map_calls if estimate_tokens(p) <= 1500]
        assert s.chunks == len(fitting)
        assert len(llm.map_calls) > len(fitting)      # some attempts overflowed first


class TestRefine:

    def test_folds_chunks_into_a_running_answer(self):
        llm = FakeLLM()
        s = LLMSummarizer(llm, strategy="refine").summarize(BIG, QUERY)
        assert s.strategy == "refine"
        assert s.chunks > 1
        assert s.text == "FINAL"
        assert not llm.map_calls                       # refine never uses the map prompt
        refine_calls = [p for p in llm.calls if "Current answer" in p]
        assert len(refine_calls) == s.chunks - 1       # first chunk uses the stuff prompt


class TestTruncation:
    """The measured trap: a thinking model can spend the whole budget reasoning and
    return an empty string with no error. An incomplete summary must say so."""

    def test_a_truncated_call_marks_the_summary(self):
        llm = FakeLLM(truncate_calls={0})
        s = LLMSummarizer(llm).summarize(SMALL, QUERY)
        assert s.truncated is True

    def test_one_truncated_map_call_is_enough(self):
        llm = FakeLLM(truncate_calls={2})
        s = LLMSummarizer(llm).summarize(BIG, QUERY)
        assert s.truncated is True

    def test_clean_runs_are_not_flagged(self):
        assert LLMSummarizer(FakeLLM()).summarize(BIG, QUERY).truncated is False


class TestConcurrency:

    def test_fan_out_changes_nothing_but_the_clock(self):
        """pool.map keeps chunk order, so the merge input -- and the answer -- is the
        same whether chunks ran one at a time or four at a time."""
        sequential = LLMSummarizer(FakeLLM()).summarize(BIG, QUERY)
        fanned = LLMSummarizer(FakeLLM(), concurrency=4).summarize(BIG, QUERY)
        assert fanned.text == sequential.text
        assert fanned.chunks == sequential.chunks
        assert fanned.strategy == sequential.strategy
