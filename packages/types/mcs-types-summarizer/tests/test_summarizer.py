"""LLMSummarizer against a scripted fake -- no model, no network, deterministic.

The fake speaks the port's portable core and recognises the summarizer's prompts by
their fixed phrases, which doubles as a check that those phrases exist: if a template
loses its marker, the fake answers wrongly and the assertions catch it.
"""

from __future__ import annotations

import re

import pytest

from mcs.types.llm import (
    DEFAULT_CHARS_PER_TOKEN,
    ContextWindowExceeded,
    LLMPort,
    LLMResponse,
    ModelInfo,
    TokenUsage,
    estimate_tokens,
)
from mcs.types.summarizer import NO_CONTENT, LLMSummarizer, Summary, SummarizerPort


class FakeLLM:
    """Deterministic LLMPort: answers by prompt kind, records calls, optional window."""

    def __init__(self, window_tokens=None, map_answer="PART", final_answer="FINAL",
                 truncate_calls=(), model=None):
        self.calls: list[str] = []
        self.window = window_tokens
        #: LLMPort.model -- what is CURRENTLY behind this port; tests reassign it to
        #: play the agent that switches models mid-operation.
        self.model = model
        self.map_answer = map_answer
        self.final_answer = final_answer
        self.truncate = set(truncate_calls)

    def describe(self):
        return None                        # LLMPort.describe: nothing to ask

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
            # Honest usage, like a real backend: report what the prompt holds. A fixed
            # number would look like silent clipping to the truncation detector.
            usage=TokenUsage(prompt=estimate_tokens(prompt), completion=7),
            finish_reason="length" if n in self.truncate else "stop",
        )

    @property
    def map_calls(self):
        return [p for p in self.calls if "one part of a larger document" in p]

    @property
    def merge_calls(self):
        return [p for p in self.calls if "Partial answers" in p]


#: ~19k characters over 30 paragraphs -- far beyond the assumed-window budget.
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

    def test_a_verbose_sentinel_is_still_a_sentinel(self):
        """Live finding: models decorate the sentinel and then explain themselves at
        length. Those essays must not enter the merge as partial answers -- a leading
        sentinel means no-content no matter how much excuse follows."""
        essay = (NO_CONTENT + " -- this part of the page only contains navigation "
                 "links, a language picker and footer boilerplate, none of which "
                 "helps with the question.")
        llm = FakeLLM(map_answer=lambda p: "TREFFER" if "Absatz 7:" in p else essay)
        s = LLMSummarizer(llm).summarize(BIG, QUERY)
        assert s.text == "TREFFER"
        assert not llm.merge_calls                    # essays never reached a merge


class TestWindowResolution:
    """Who decides the window, in order of knowledge: the constructor (the developer
    may know a serving truth no endpoint states), the port's own statement
    (describe(), once per model id), the conservative assumption. Learning corrects
    all three -- see TestSilentTruncation for the statement-vs-reality case."""

    class StatingLLM(FakeLLM):
        """A port whose backend states its window -- and counts being asked."""

        def __init__(self, stated_window=65_536, **kw):
            super().__init__(**kw)
            self.stated_window = stated_window
            self.describe_calls = 0

        def describe(self):
            self.describe_calls += 1
            return ModelInfo(context_window=self.stated_window)

    def test_the_port_is_asked_when_the_constructor_is_silent(self):
        """BIG does not fit the assumed 4096, but fits a stated 65536: one stuff call
        instead of a map/merge cascade -- the statement was actually planned with."""
        llm = self.StatingLLM(stated_window=65_536)
        s = LLMSummarizer(llm).summarize(BIG, QUERY)
        assert s.strategy == "stuff"
        assert len(llm.calls) == 1
        assert llm.describe_calls == 1

    def test_the_constructor_wins_over_the_statement(self):
        """The developer's number is deployment truth (Ollama's num_ctx); a grander
        statement must not override it -- and there is nothing left to ask."""
        llm = self.StatingLLM(stated_window=262_144)
        s = LLMSummarizer(llm, context_window=4096).summarize(BIG, QUERY)
        assert s.strategy == "map_reduce"        # planned with 4096, not 262144
        assert llm.describe_calls == 0

    def test_silence_falls_back_to_the_assumption(self):
        """describe() -> None (a BYO wrapper): the conservative assumption applies."""
        s = LLMSummarizer(FakeLLM()).summarize(BIG, QUERY)
        assert s.strategy == "map_reduce"

    def test_the_inquiry_happens_once_per_model_not_per_run(self):
        """The answer is cached per model id -- but a router switching models is a NEW
        question, asked exactly once more."""
        llm = self.StatingLLM(stated_window=65_536, model="a")
        summarizer = LLMSummarizer(llm)
        summarizer.summarize(BIG, QUERY)
        summarizer.summarize(BIG, QUERY)
        assert llm.describe_calls == 1
        llm.model = "b"                          # the agent switches mid-operation
        summarizer.summarize(BIG, QUERY)
        assert llm.describe_calls == 2

    def test_one_models_lesson_is_not_anothers_budget(self):
        """Windows are held per model id: what an overflow taught about model 'a'
        must not shrink the freshly stated window of model 'b'."""
        llm = self.StatingLLM(stated_window=65_536, model="a")
        summarizer = LLMSummarizer(llm)
        summarizer.summarize(BIG, QUERY)
        summarizer._learn(ContextWindowExceeded(limit=2048))   # 'a' hits a wall
        assert summarizer._windows["a"] == 2048
        llm.model = "b"
        summarizer.summarize(BIG, QUERY)
        assert summarizer._windows["b"] == 65_536              # untouched by 'a'


class TestSilentTruncation:
    """Measured against a local Ollama: input beyond num_ctx is dropped with NO error
    -- the prompt's start is cut, finish_reason says "stop", usage reports exactly the
    window. The summarizer turns that into the overflow it should have been, using the
    one measurement the backend cannot help giving: its own usage report."""

    class ClippingLLM(FakeLLM):
        """Reports far fewer processed prompt tokens than the prompt holds."""

        def __init__(self, effective_window=100, **kw):
            super().__init__(**kw)
            self.effective = effective_window

        def complete(self, prompt, *, system=None, max_completion_tokens=None, **kw):
            r = super().complete(prompt, system=system,
                                 max_completion_tokens=max_completion_tokens)
            reported = min(self.effective, estimate_tokens(prompt))
            return LLMResponse(text=r.text, finish_reason=r.finish_reason,
                               usage=TokenUsage(prompt=reported, completion=7))

    def test_clipping_is_detected_and_relearned(self):
        """A 100k-window claim against a tiny effective window: the mismatch between
        estimate and report raises, auto falls back, and the *report* becomes the
        window -- floored, so re-chunking converges instead of looping."""
        llm = self.ClippingLLM(effective_window=100)
        summarizer = LLMSummarizer(llm, context_window=100_000)
        s = summarizer.summarize(BIG, QUERY)
        assert s.strategy == "map_reduce"             # stuff answer was discarded
        assert s.chunks > 1
        assert summarizer._window == 1024             # max(1024, reported 100)

    def test_an_honest_backend_is_not_second_guessed(self):
        """Reports close to the estimate (or absent) must never trigger: the estimate
        is +-30%, so only gross clipping is provable. FakeLLM reports honestly, and
        every other test in this file doubles as a no-false-alarm check."""
        s = LLMSummarizer(FakeLLM()).summarize(BIG, QUERY)
        assert s.strategy == "map_reduce"             # ran to completion, no relearning
        assert s.text == "FINAL"

    def test_a_statement_is_not_a_guarantee(self):
        """Measured on Ollama: the endpoint states the model card's 262144 while
        serving a far smaller num_ctx. The clip detector, not the statement, has the
        last word -- the stated window is demoted the moment usage proves it wrong."""
        class StatingClippingLLM(TestSilentTruncation.ClippingLLM):
            def describe(self):
                return ModelInfo(context_window=262_144)
        llm = StatingClippingLLM(effective_window=100)
        summarizer = LLMSummarizer(llm)          # no constructor window: trusts... briefly
        s = summarizer.summarize(BIG, QUERY)
        assert s.strategy == "map_reduce"        # the stated-window stuff was discarded
        assert summarizer._window == 1024        # max(1024, reported 100)

    def test_usage_is_summed_over_every_call(self):
        llm = FakeLLM()
        s = LLMSummarizer(llm).summarize(BIG, QUERY)
        assert s.usage.prompt == sum(estimate_tokens(p) for p in llm.calls)
        assert s.usage.completion == 7 * len(llm.calls)
        assert s.usage.reasoning is None       # never reported -> stays None, not 0

    def test_document_order_survives_chunking_into_the_merge(self):
        """The live finding, pinned on the machinery's side: chunks are mapped and
        merged in document order -- splitting keeps it, ``pool.map`` keeps it, the
        merge prompt lists partials in it. Any re-sorting can therefore only happen
        *inside* a model call, which is what the templates now forbid. Each map answer
        here echoes its chunk's first paragraph number; the merge prompt must list
        them ascending -- sequentially and fanned out alike."""
        def echo_first_paragraph(prompt):
            return "M" + re.search(r"Absatz (\d+):", prompt).group(1)

        def merge_order(concurrency):
            llm = FakeLLM(map_answer=echo_first_paragraph)
            LLMSummarizer(llm, concurrency=concurrency).summarize(BIG, QUERY)
            first_merge = llm.merge_calls[0]
            return [int(m) for m in re.findall(r"- M(\d+)", first_merge)]

        sequential = merge_order(1)
        assert len(sequential) > 1
        assert sequential == sorted(sequential)        # document order, ascending
        assert merge_order(4) == sequential            # fan-out changes nothing


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
        summarizer = LLMSummarizer(llm, context_window=100_000)  # claim: everything fits
        s = summarizer.summarize(BIG, QUERY)
        assert s.strategy == "map_reduce"
        assert s.chunks > 1
        # The named limit IS the window -- it replaces the 100k claim outright
        # (floored at 1024, below which no real model lives).
        assert summarizer._window == 1024

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


class TestPromptLoading:
    """No prompt is hardcoded: the texts ship as package data (prompts/default.toml),
    the developer replaces them sparsely, and model variants select tuned phrasings.
    The mechanism is mcs-prompts; what these tests pin is the summarizer's use of it."""

    def test_a_sparse_override_replaces_one_template(self):
        llm = FakeLLM()
        s = LLMSummarizer(llm, prompts={"stuff": "CUSTOM {query} :: {text}"})
        s.summarize(SMALL, QUERY)
        assert llm.calls[0].startswith("CUSTOM Wie heisst die Katze?")

    def test_variants_follow_the_port_not_a_constructor(self, tmp_path):
        """The port names its model; the summarizer resolves per run. Nobody passes a
        model id into this component -- it asks the one party that knows."""
        f = tmp_path / "mine.toml"
        f.write_text(
            '[prompts."model:qwen*"]\n'
            'stuff = "QWENVARIANTE: {query}\\n{text}"\n',
            encoding="utf-8",
        )
        tuned = FakeLLM(model="qwen3:4b")
        LLMSummarizer(tuned, prompts=f).summarize(SMALL, QUERY)
        assert tuned.calls[0].startswith("QWENVARIANTE:")

        untouched = FakeLLM(model="gpt-5.6")
        LLMSummarizer(untouched, prompts=f).summarize(SMALL, QUERY)
        assert untouched.calls[0].startswith("Question:")      # base stays base

    def test_variants_follow_a_model_switch_mid_operation(self, tmp_path):
        """The reason resolution happens per RUN: an agent may switch models between
        calls (a router port falls back, the client swaps tiers). Same summarizer,
        same bundle -- the prompts follow the port's current answer."""
        f = tmp_path / "mine.toml"
        f.write_text(
            '[prompts."model:qwen*"]\n'
            'stuff = "QWENVARIANTE: {query}\\n{text}"\n',
            encoding="utf-8",
        )
        llm = FakeLLM(model="gpt-5.6")
        summarizer = LLMSummarizer(llm, prompts=f)
        summarizer.summarize(SMALL, QUERY)
        assert llm.calls[-1].startswith("Question:")           # frontier: base prompts

        llm.model = "qwen3:4b"                                 # the agent switched
        summarizer.summarize(SMALL, QUERY)
        assert llm.calls[-1].startswith("QWENVARIANTE:")       # ...prompts followed

    def test_a_custom_sentinel_keeps_template_and_filter_in_sync(self):
        """The map template carries the sentinel via {no_content}, and the filter reads
        the same loaded value -- overriding one place changes both, by construction."""
        llm = FakeLLM(map_answer="GAR NICHTS")
        s = LLMSummarizer(llm, prompts={"no_content": "GAR NICHTS"}).summarize(BIG, QUERY)
        assert "GAR NICHTS" in llm.map_calls[0]                # template asks for it
        assert s.text == ""                                    # filter recognises it
        assert not llm.merge_calls


class TestCalibration:
    """The a-priori chars-per-token ratio is a labelled guess; measured usage is the
    truth. The summarizer adopts measured ratios -- downward only, toward safety."""

    class DenseTokenLLM(FakeLLM):
        """Reports usage as if text packed ~1.5 chars/token (CJK, code, markup)."""

        def complete(self, prompt, *, system=None, max_completion_tokens=None, **kw):
            r = super().complete(prompt, system=system,
                                 max_completion_tokens=max_completion_tokens)
            return LLMResponse(text=r.text, finish_reason=r.finish_reason,
                               usage=TokenUsage(prompt=int(len(prompt) / 1.5),
                                                completion=7))

    class SparseTokenLLM(FakeLLM):
        """Reports usage as if text packed ~5 chars/token (airy English prose)."""

        def complete(self, prompt, *, system=None, max_completion_tokens=None, **kw):
            r = super().complete(prompt, system=system,
                                 max_completion_tokens=max_completion_tokens)
            return LLMResponse(text=r.text, finish_reason=r.finish_reason,
                               usage=TokenUsage(prompt=max(1, int(len(prompt) / 5)),
                                                completion=7))

    def test_denser_reality_tightens_the_ratio(self):
        """The dangerous direction -- estimates too low, budgets overflow -- is
        corrected automatically from the first measurement."""
        summarizer = LLMSummarizer(self.DenseTokenLLM())
        summarizer.summarize(SMALL, QUERY)
        assert summarizer._chars_per_token < 2.0           # adopted ~1.5

    def test_cheaper_reality_is_not_adopted(self):
        """Staying conservative costs one extra chunk at worst; drifting optimistic
        could cost an overflow. Loosening stays the developer's explicit call."""
        summarizer = LLMSummarizer(self.SparseTokenLLM())
        summarizer.summarize(SMALL, QUERY)
        assert summarizer._chars_per_token == DEFAULT_CHARS_PER_TOKEN


class TestConcurrency:

    def test_fan_out_changes_nothing_but_the_clock(self):
        """pool.map keeps chunk order, so the merge input -- and the answer -- is the
        same whether chunks ran one at a time or four at a time."""
        sequential = LLMSummarizer(FakeLLM()).summarize(BIG, QUERY)
        fanned = LLMSummarizer(FakeLLM(), concurrency=4).summarize(BIG, QUERY)
        assert fanned.text == sequential.text
        assert fanned.chunks == sequential.chunks
        assert fanned.strategy == sequential.strategy
