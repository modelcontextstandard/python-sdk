"""LLMSummarizer -- the default query-focused summarizer over an injected LLMPort.

Strategies carry the established names (LangChain / LlamaIndex vocabulary):

- ``"stuff"``: one call with the whole text -- when it fits.
- ``"map_reduce"``: ask every chunk independently, then merge the partial answers --
  recursively when they do not fit one merge call, which is the bottom-up tree others
  call ``tree_summarize``. **The promotion default when stuff does not fit**, because it
  is order-independent: the same document yields the same evidence no matter which chunk
  answered first. Chunks run sequentially by default; ``concurrency=N`` fans them out.
- ``"refine"``: fold chunk after chunk into a running answer. Fewer calls, no merge --
  but order-dependent by design, so it is a choice, never the silent default.
- ``"auto"`` (the default): stuff when the estimate fits ``chunk_tokens``, else
  map_reduce -- and stuff falls back to map_reduce when the backend proves the estimate
  wrong.

**The summarizer thinks in the model's context window** -- the number a developer
actually has, straight off the model card. Everything else is derived:

    input budget per call = context_window - answer reserve - template overhead

The window resolves in three steps, best knowledge first. The **constructor** wins:
the developer may know a serving truth no endpoint states (Ollama serves its
``num_ctx``, not the model card). Unset, the summarizer **asks the port** --
``LLMPort.describe()``, once per model id -- and plans with what the backend states;
it may do so because the inquiry is part of the very contract it already holds.
Where nothing is stated either, a conservative assumption applies. All three are then
corrected by the backend itself: a call that comes back with
``ContextWindowExceeded`` *learns* -- a named limit **is** the window and replaces the
guess outright; without a name, halving is all there is. The same document never hits
the same wall twice. This state lives here and not on the adapter because it is
planning knowledge, held by the component doing the planning -- per model id, like
the prompt variants, so an agent that switches models mid-operation never plans one
model's budget with another model's lesson.

**Truncation is propagated, never swallowed.** Measured on qwen3 via Ollama: a
reasoning model can spend an entire answer budget thinking and return an empty string
with no error at all. Any answer along the way that hit its cap marks the whole
``Summary`` as ``truncated`` -- an incomplete summary must never look like a short one.

Only the port's **portable core** is used: ``prompt``, ``system``,
``max_completion_tokens``. No sampling, no backend-specific kwargs -- this component
runs on whatever model it is lent, which is the discipline the port's docstring asks of
reusable components.
"""

from __future__ import annotations

from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from mcs.prompts import load_prompts
from mcs.types.llm import (
    DEFAULT_CHARS_PER_TOKEN,
    ContextWindowExceeded,
    LLMPort,
    LLMResponse,
    TokenUsage,
    estimate_tokens,
)

from .port import Summary

#: Context window assumed before anything about the model is known. Deliberately the
#: smallest window still in real use: too small merely costs extra chunks, too large
#: costs a failed round trip. The first ``ContextWindowExceeded`` replaces this guess
#: with the backend's own number.
DEFAULT_ASSUMED_WINDOW = 4096

#: Tokens kept free for the model's *answer* when no ``max_answer_tokens`` is set. The
#: window covers prompt AND completion, so the input budget is never the whole window --
#: and a thinking model spends part of this reserve on reasoning before a word of
#: answer appears.
DEFAULT_ANSWER_RESERVE = 1024

#: Sentinel a map call answers when its chunk holds nothing relevant. Filtered before
#: merging, so the merge model never spends attention on "this part was empty" -- and so
#: a document with *no* relevant content yields an honestly empty Summary.
NO_CONTENT = "NO RELEVANT CONTENT"

#: Below this, halving a chunk cannot be what fixes an overflow -- the template and
#: query alone outweigh the text, so recursing further would only mask a real problem.
_MIN_CHUNK_CHARS = 512

_STRATEGIES = ("auto", "stuff", "map_reduce", "refine")


def _hard_split(paragraph: str, max_chars: int) -> list[str]:
    """Cut an oversized paragraph at spaces near the budget -- last-resort splitting."""
    pieces: list[str] = []
    rest = paragraph
    while len(rest) > max_chars:
        cut = rest.rfind(" ", max_chars // 2, max_chars)
        if cut <= 0:
            cut = max_chars
        pieces.append(rest[:cut])
        rest = rest[cut:].lstrip()
    if rest:
        pieces.append(rest)
    return pieces


class LLMSummarizer:
    """Query-focused summarization over an injected :class:`~mcs.types.llm.LLMPort`.

    Parameters
    ----------
    llm :
        The model to work with -- **injected, never constructed here**. A client that
        has governance (cost tracking, PII filtering) in its LLM path lends that; one
        that has none wires up an adapter. There is no silent default on purpose.
    strategy :
        One of ``auto | stuff | map_reduce | refine``. A *pinned* strategy is honoured
        even into failure: pinned ``stuff`` with an oversized text raises rather than
        silently becoming something else -- the caller asked for exactly that.
    context_window :
        The model's total token window, for when the developer knows better than the
        backend states -- Ollama's effective window is its ``num_ctx``, not the model
        card. Everything else is derived from it:

            input budget per call = context_window - answer reserve - template overhead

        where the answer reserve is *max_answer_tokens* when set, else
        :data:`DEFAULT_ANSWER_RESERVE`. **Unset, the summarizer asks the port
        itself** (``describe()``, once per model id) and plans with what the backend
        states; where nothing is stated, a conservative
        :data:`DEFAULT_ASSUMED_WINDOW` applies. Every step stays correctable: a named
        ``ContextWindowExceeded`` limit replaces the working window outright, and the
        silent-truncation detector demotes a stated-but-not-served number the moment
        usage proves it wrong.
    max_answer_tokens :
        Cap for every model answer, passed as the port's ``max_completion_tokens``.
        ``None`` (default) sets no cap: a cap is a harness decision, and a tight one
        combined with a thinking model yields empty, truncated answers. When set,
        truncation is at least *flagged* -- see ``Summary.truncated``.
    concurrency :
        Fan-out for the map phase. ``1`` (default) runs chunks sequentially -- correct
        everywhere, including local servers that serialise requests anyway. Higher
        values run map calls in threads; the merge is order-stable either way.
    prompts :
        The developer's own prompt texts: a TOML path (same layout as the shipped
        ``prompts/default.toml``, model sections allowed) or a sparse mapping
        ``name -> template``. **No prompt is hardcoded here** -- every word this
        component says to its model lives in its package's ``prompts/default.toml``
        and is replaced, never edited, through this parameter. The system prompt is
        one of them (``"system"``).

        There is deliberately **no** model parameter: which prompt variants apply is
        decided per *run*, not per construction. The port names the model currently
        behind it (``LLMPort.model``), and every ``summarize`` call resolves the
        bundle for exactly that -- so an agent that switches models mid-operation, or
        a router port that falls back, gets the matching phrasings without anyone
        reconfiguring this component.
    chars_per_token :
        Estimation ratio while nothing has been measured. The default is deliberately
        conservative; see :func:`mcs.types.llm.estimate_tokens`.
    """

    def __init__(
        self,
        llm: LLMPort,
        *,
        strategy: str = "auto",
        context_window: int | None = None,
        max_answer_tokens: int | None = None,
        concurrency: int = 1,
        prompts: "str | Path | Mapping[str, str] | None" = None,
        chars_per_token: float = DEFAULT_CHARS_PER_TOKEN,
    ) -> None:
        if strategy not in _STRATEGIES:
            raise ValueError(f"strategy must be one of {_STRATEGIES}, not {strategy!r}")
        if concurrency < 1:
            raise ValueError("concurrency must be >= 1")
        self._llm = llm
        self._strategy = strategy
        self._pinned = strategy != "auto"
        self._configured_window = context_window
        #: Working window per model id -- resolved lazily in :meth:`summarize`, learned
        #: in :meth:`_learn`. Per model, like the prompt variants: a router port may
        #: switch models mid-operation, and one model's lesson is not another's budget.
        self._windows: dict[str | None, int] = {}
        self._current: str | None = None
        self._max_answer_tokens = max_answer_tokens
        self._concurrency = concurrency
        self._chars_per_token = chars_per_token
        # Loaded once, resolved per run: see the `prompts` parameter docs.
        self._bundle = load_prompts("mcs.types.summarizer", override=prompts)
        self._active = self._bundle.resolve(None)

    # -- the per-model window --------------------------------------------------

    @property
    def _window(self) -> int:
        """Working window of the model currently behind the port."""
        return self._windows.get(self._current, DEFAULT_ASSUMED_WINDOW)

    @_window.setter
    def _window(self, value: int) -> None:
        self._windows[self._current] = value

    def _resolve_window(self) -> int:
        """First window for a model this instance has not planned for yet.

        Best knowledge first: the constructor (the developer may know a serving truth
        no endpoint states), then the port's own statement -- ``describe()`` is part
        of the contract this component already holds, so asking it is using the
        injected port, not opening a side channel -- then the conservative
        assumption. Whatever this returns is a starting point, not a verdict: the
        learning in :meth:`_learn` and the silent-truncation detector correct it the
        moment the backend proves otherwise.
        """
        if self._configured_window:
            return self._configured_window
        describe = getattr(self._llm, "describe", None)
        stated = describe() if callable(describe) else None
        if stated is not None and stated.context_window:
            return stated.context_window
        return DEFAULT_ASSUMED_WINDOW

    # -- the per-run prompt view ----------------------------------------------

    @property
    def _system(self) -> str:
        return self._active["system"]

    @property
    def _no_content(self) -> str:
        return self._active.get("no_content", NO_CONTENT)

    # -- SummarizerPort --------------------------------------------------------

    def summarize(self, text: str, query: str) -> Summary:
        if not text or not text.strip():
            raise ValueError("Nothing to condense: text is empty.")
        if not query or not query.strip():
            raise ValueError(
                "No intent to condense under: query is empty. This is query-focused "
                "summarization -- ask something, even if it is 'summarise this text'."
            )

        # Prompts AND window follow the model AT CALL TIME: the port names what is
        # currently behind it (a router may have switched since the last run), the
        # bundle resolves the variants for exactly that, and an unseen model gets its
        # window resolved once -- both cached per id, so the common case costs two
        # dictionary lookups.
        model = getattr(self._llm, "model", None)
        self._active = self._bundle.resolve(model)
        self._current = model
        if model not in self._windows:
            self._windows[model] = self._resolve_window()

        responses: list[LLMResponse] = []
        strategy = self._strategy
        if strategy == "auto":
            fits = estimate_tokens(
                self._active["stuff"].format(query=query, text=text),
                self._chars_per_token,
            ) <= self._input_budget()
            strategy = "stuff" if fits else "map_reduce"

        if strategy == "stuff":
            try:
                r = self._ask(self._active["stuff"].format(query=query, text=text))
                responses.append(r)
                return self._summary(r.text, query, "stuff", 1, responses)
            except ContextWindowExceeded as exc:
                if self._pinned:
                    raise            # the caller asked for exactly this; failing IS the answer
                self._learn(exc)
                strategy = "map_reduce"

        if strategy == "map_reduce":
            answer, leaves = self._map_reduce(text, query, responses)
            return self._summary(answer, query, "map_reduce", leaves, responses)

        answer, leaves = self._refine(text, query, responses)
        return self._summary(answer, query, "refine", leaves, responses)

    # -- map_reduce ------------------------------------------------------------

    def _map_reduce(
        self, text: str, query: str, responses: list[LLMResponse],
    ) -> tuple[str, int]:
        chunks = self._split(text, query)
        if self._concurrency > 1 and len(chunks) > 1:
            with ThreadPoolExecutor(
                max_workers=min(self._concurrency, len(chunks))
            ) as pool:
                results = list(pool.map(lambda c: self._map_chunk(c, query), chunks))
        else:
            results = [self._map_chunk(c, query) for c in chunks]

        # `results` is in chunk order regardless of thread scheduling (pool.map keeps
        # order), so the merge input -- and with it the answer -- is deterministic.
        partials = [a for answers, _ in results for a in answers]
        map_responses = [r for _, rs in results for r in rs]
        responses.extend(map_responses)
        leaves = len(map_responses)

        if not partials:
            return "", leaves        # nothing relevant anywhere: an answer, not a failure
        if len(partials) == 1:
            return partials[0], leaves
        return self._merge(partials, query, responses), leaves

    def _map_chunk(self, chunk: str, query: str) -> tuple[list[str], list[LLMResponse]]:
        """Ask one chunk; on overflow, learn and split it -- every leaf gets read."""
        try:
            r = self._ask(self._active["map"].format(query=query, text=chunk,
                                                      no_content=self._no_content))
        except ContextWindowExceeded as exc:
            self._learn(exc)
            if len(chunk) <= _MIN_CHUNK_CHARS:
                raise                # halving cannot save this; surface the real problem
            mid = len(chunk) // 2
            left_a, left_r = self._map_chunk(chunk[:mid], query)
            right_a, right_r = self._map_chunk(chunk[mid:], query)
            return left_a + right_a, left_r + right_r
        answers = [] if self._is_no_content(r.text) else [r.text.strip()]
        return answers, [r]

    def _merge(
        self, partials: list[str], query: str, responses: list[LLMResponse],
    ) -> str:
        """Merge partial answers, in rounds, until one remains.

        Each round packs answers into groups that fit the working budget and merges
        every group with one call. Groups hold at least two answers whenever possible,
        so every round strictly shrinks the list -- this bottom-up recursion is what
        LlamaIndex calls ``tree_summarize``.
        """
        answers = list(partials)
        while len(answers) > 1:
            budget_chars = self._budget_chars(self._active["merge"], query)
            merged: list[str] = []
            group: list[str] = []
            group_len = 0
            for a in answers:
                if len(group) >= 2 and group_len + len(a) > budget_chars:
                    merged.append(self._merge_group(group, query, responses))
                    group, group_len = [], 0
                group.append(a)
                group_len += len(a) + 2
            merged.append(self._merge_group(group, query, responses))
            answers = merged
        return answers[0]

    def _merge_group(
        self, group: list[str], query: str, responses: list[LLMResponse],
    ) -> str:
        if len(group) == 1:
            return group[0]
        joined = "\n\n".join(f"- {a}" for a in group)
        try:
            r = self._ask(self._active["merge"].format(query=query, text=joined))
        except ContextWindowExceeded as exc:
            self._learn(exc)
            if len(group) == 2:
                raise                # two answers alone exceed the window: unsplittable
            mid = len(group) // 2
            halves = [
                self._merge_group(group[:mid], query, responses),
                self._merge_group(group[mid:], query, responses),
            ]
            return self._merge_group(halves, query, responses)
        responses.append(r)
        return r.text.strip()

    # -- refine ----------------------------------------------------------------

    def _refine(
        self, text: str, query: str, responses: list[LLMResponse],
    ) -> tuple[str, int]:
        pending = list(reversed(self._split(text, query)))
        answer: str | None = None
        leaves = 0
        while pending:
            chunk = pending.pop()
            prompt = (
                self._active["stuff"].format(query=query, text=chunk)
                if answer is None
                else self._active["refine"].format(query=query, answer=answer,
                                                    text=chunk)
            )
            try:
                r = self._ask(prompt)
            except ContextWindowExceeded as exc:
                self._learn(exc)
                if len(chunk) <= _MIN_CHUNK_CHARS:
                    raise
                mid = len(chunk) // 2
                pending.append(chunk[mid:])
                pending.append(chunk[:mid])
                continue
            responses.append(r)
            answer = r.text.strip()
            leaves += 1
        return answer or "", leaves

    # -- shared machinery ------------------------------------------------------

    def _ask(self, prompt: str) -> LLMResponse:
        """One model call, portable core only -- see the module docstring."""
        response = self._llm.complete(
            prompt, system=self._system,
            max_completion_tokens=self._max_answer_tokens,
        )
        self._check_silent_truncation(prompt, response)
        self._calibrate(prompt, response)
        return response

    def _calibrate(self, prompt: str, response: LLMResponse) -> None:
        """Replace the guessed chars-per-token ratio with measurement -- downward only.

        The a-priori ratio is a labelled guess (see :mod:`mcs.types.llm.tokens`); every
        response carries the truth for THIS model and THIS kind of text in its measured
        prompt tokens. When reality packs more tokens into the same characters than
        assumed (CJK, code, markup), guess-based budgets overflow -- so a denser
        measured ratio replaces the guess for every call after.

        Downward only, deliberately. Learning that text is *cheaper* than assumed
        would trade a proven-safe budget for fewer chunks; that optimisation is the
        developer's explicit call (``chars_per_token=``), not something to drift into.
        The rule doubles as a corruption guard: a silent clip below the detection
        threshold inflates the measured ratio -- and inflated ratios fall on the
        ignored side. (The denominator also includes system prompt and chat-template
        overhead, biasing measurements slightly conservative -- same direction, fine.)
        """
        reported = response.usage.input
        if reported and reported > 0:
            measured = len(prompt) / reported
            if measured < self._chars_per_token:
                self._chars_per_token = max(1.0, measured)

    def _check_silent_truncation(self, prompt: str, response: LLMResponse) -> None:
        """Turn a backend's silent clipping into the loud failure it should have been.

        Measured against a local Ollama: input beyond ``num_ctx`` is dropped without
        any error -- the *start* of the prompt is cut, ``finish_reason`` says
        ``"stop"``, and usage dutifully reports exactly the window (32 767 for
        ``num_ctx=32768``). The overflow exception our whole learning mechanism waits
        for never fires there, and an answer computed from half the document would
        sail through as genuine.

        The measured usage is the tell: a backend that reports processing far fewer
        tokens than the prompt holds read a fraction of it. Coarse thresholds on
        purpose -- the estimate is ±30%, so only gross clipping is provable from here.
        A 1M-window claim against a 4k ``num_ctx`` is caught and relearned; a 10% trim
        is not detectable by arithmetic and stays the operator's job (set ``num_ctx``
        to match the model card).
        """
        reported = response.usage.input
        if reported is None:
            return
        estimated = estimate_tokens(prompt, self._chars_per_token)
        if estimated > reported * 2 and estimated - reported > 512:
            raise ContextWindowExceeded(
                f"The backend reports {reported} processed prompt tokens for a prompt "
                f"holding an estimated {estimated}: it silently truncated the input "
                "(Ollama clips at num_ctx without an error). Treating the report as "
                "the effective window.",
                limit=reported,
            )

    def _input_budget(self) -> int:
        """Tokens of *payload* one call may carry: the window minus the answer reserve.

        The window covers prompt and completion together, so the reserve comes off
        first -- *max_answer_tokens* when the caller set one, else a default that
        leaves a thinking model room to think. Template overhead is subtracted later,
        per template, in :meth:`_budget_chars`.
        """
        reserve = self._max_answer_tokens or DEFAULT_ANSWER_RESERVE
        return max(256, self._window - reserve)

    def _learn(self, exc: ContextWindowExceeded) -> None:
        """Correct the working window from what a failure just taught.

        A named limit *is* the window -- the backend stated its capacity, so it
        replaces the guess outright rather than feeding some derived fraction. Without
        a name, halving is all there is. Kept on the instance: the next chunk, and the
        next document through this summarizer, start from reality.
        """
        if exc.limit:
            self._window = min(self._window, max(1024, exc.limit))
        else:
            self._window = max(1024, self._window // 2)

    def _split(self, text: str, query: str) -> list[str]:
        """Pack paragraphs into chunks that fit the working budget."""
        max_chars = self._budget_chars(self._active["map"], query)
        chunks: list[str] = []
        current = ""
        for para in text.split("\n\n"):
            if len(para) > max_chars:
                if current:
                    chunks.append(current)
                    current = ""
                chunks.extend(_hard_split(para, max_chars))
            elif not current:
                current = para
            elif len(current) + len(para) + 2 <= max_chars:
                current = f"{current}\n\n{para}"
            else:
                chunks.append(current)
                current = para
        if current:
            chunks.append(current)
        return chunks or [text]

    def _budget_chars(self, template: str, query: str) -> int:
        """How many characters of payload fit one call, after template and headroom.

        The full derivation, in one place: window - answer reserve (via
        :meth:`_input_budget`) - this template with the query already in it - a small
        margin for the estimate being an estimate.
        """
        skeleton = template.format(query=query, text="", answer="",
                                   no_content=self._no_content)
        usable = max(256, self._input_budget() - estimate_tokens(
            skeleton, self._chars_per_token) - 64)
        return int(usable * self._chars_per_token)

    def _is_no_content(self, text: str) -> bool:
        t = text.strip()
        if not t:
            return True
        # Lenient by POSITION, not length: models decorate the sentinel and then
        # explain themselves ("NO RELEVANT CONTENT -- this part is only navigation
        # links, a language picker, ..."). Under a length rule those essays counted as
        # partial answers and diluted the merge with non-answers; a sentinel that
        # leads the reply means no-content no matter how much excuse follows.
        #
        # The sentinel is the LOADED one, not the module constant: the map template
        # carries it via {no_content}, so template and filter stay in sync however the
        # prompts are overridden.
        sentinel = self._no_content.upper()
        return sentinel in t[:len(sentinel) + 46].upper()

    def _summary(
        self, text: str, query: str, strategy: str, chunks: int,
        responses: list[LLMResponse],
    ) -> Summary:
        return Summary(
            text=text.strip(),
            query=query,
            strategy=strategy,
            chunks=chunks,
            truncated=any(r.truncated for r in responses),
            usage=self._aggregate(responses),
        )

    @staticmethod
    def _aggregate(responses: list[LLMResponse]) -> TokenUsage:
        """Sum measured usage across calls; a field nobody reported stays ``None``."""
        def total(name: str) -> int | None:
            values = [getattr(r.usage, name) for r in responses
                      if getattr(r.usage, name) is not None]
            return sum(values) if values else None
        return TokenUsage(input=total("input"), output=total("output"),
                          total=total("total"), reasoning=total("reasoning"),
                          cache_read=total("cache_read"),
                          cache_write=total("cache_write"))
