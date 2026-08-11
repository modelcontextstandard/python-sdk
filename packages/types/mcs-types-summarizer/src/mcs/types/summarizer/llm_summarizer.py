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

**The planner remembers; the transport does not.** ``LLMPort`` deliberately reports no
context window, so the budget is discovered by working: this class starts from
``chunk_tokens`` and, when a call comes back with ``ContextWindowExceeded``, *learns* --
the limit the backend named (or a halving, when it named none) shrinks the working
budget for everything that follows. The same document never hits the same wall twice.
That state lives here and not on the adapter because it is planning knowledge, held by
the component doing the planning.

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

from concurrent.futures import ThreadPoolExecutor

from mcs.types.llm import (
    DEFAULT_CHARS_PER_TOKEN,
    ContextWindowExceeded,
    LLMPort,
    LLMResponse,
    TokenUsage,
    estimate_tokens,
)

from .port import Summary

#: Working budget (in tokens) per model call before anything about the model is known.
#: Conservative enough to fit every >=4k window with template and answer headroom; the
#: first ``ContextWindowExceeded`` replaces this guess with the backend's own number.
DEFAULT_CHUNK_TOKENS = 3000

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
    chunk_tokens :
        Starting per-call budget. Shrinks when the backend teaches a smaller reality.
    max_answer_tokens :
        Cap for every model answer, passed as the port's ``max_completion_tokens``.
        ``None`` (default) sets no cap: a cap is a harness decision, and a tight one
        combined with a thinking model yields empty, truncated answers. When set,
        truncation is at least *flagged* -- see ``Summary.truncated``.
    concurrency :
        Fan-out for the map phase. ``1`` (default) runs chunks sequentially -- correct
        everywhere, including local servers that serialise requests anyway. Higher
        values run map calls in threads; the merge is order-stable either way.
    system :
        Steering for every call. The default pins the model to the text ("answer
        strictly from the provided text"), which is what query-focused condensation
        means -- replace it consciously or not at all.
    chars_per_token :
        Estimation ratio while nothing has been measured. The default is deliberately
        conservative; see :func:`mcs.types.llm.estimate_tokens`.

    Prompt templates are class attributes (``STUFF_TEMPLATE`` and friends) -- subclass
    to rephrase them without touching the machinery.
    """

    SYSTEM = ("You answer strictly from the provided text. Be precise and complete; "
              "do not add outside knowledge.")

    STUFF_TEMPLATE = ("Question: {query}\n\nText:\n{text}\n\n"
                      "Answer the question using only the text above.")

    MAP_TEMPLATE = ("Question: {query}\n\nText (one part of a larger document):\n{text}\n\n"
                    "Extract everything from this part that helps answer the question, "
                    "keeping exact figures and names. If nothing in this part helps, "
                    "reply exactly: " + NO_CONTENT)

    MERGE_TEMPLATE = ("Question: {query}\n\nPartial answers gathered from different "
                      "parts of one document:\n{text}\n\n"
                      "Combine them into one coherent answer to the question. Remove "
                      "duplicates; keep every distinct fact.")

    REFINE_TEMPLATE = ("Question: {query}\n\nCurrent answer:\n{answer}\n\n"
                       "Additional text:\n{text}\n\n"
                       "Improve the current answer using the additional text. If it "
                       "adds nothing, return the current answer unchanged.")

    def __init__(
        self,
        llm: LLMPort,
        *,
        strategy: str = "auto",
        chunk_tokens: int = DEFAULT_CHUNK_TOKENS,
        max_answer_tokens: int | None = None,
        concurrency: int = 1,
        system: str | None = None,
        chars_per_token: float = DEFAULT_CHARS_PER_TOKEN,
    ) -> None:
        if strategy not in _STRATEGIES:
            raise ValueError(f"strategy must be one of {_STRATEGIES}, not {strategy!r}")
        if concurrency < 1:
            raise ValueError("concurrency must be >= 1")
        self._llm = llm
        self._strategy = strategy
        self._pinned = strategy != "auto"
        self._chunk_tokens = chunk_tokens
        self._max_answer_tokens = max_answer_tokens
        self._concurrency = concurrency
        self._system = system if system is not None else self.SYSTEM
        self._chars_per_token = chars_per_token

    # -- SummarizerPort --------------------------------------------------------

    def summarize(self, text: str, query: str) -> Summary:
        if not text or not text.strip():
            raise ValueError("Nothing to condense: text is empty.")
        if not query or not query.strip():
            raise ValueError(
                "No intent to condense under: query is empty. This is query-focused "
                "summarization -- ask something, even if it is 'summarise this text'."
            )

        responses: list[LLMResponse] = []
        strategy = self._strategy
        if strategy == "auto":
            fits = estimate_tokens(
                self.STUFF_TEMPLATE.format(query=query, text=text),
                self._chars_per_token,
            ) <= self._chunk_tokens
            strategy = "stuff" if fits else "map_reduce"

        if strategy == "stuff":
            try:
                r = self._ask(self.STUFF_TEMPLATE.format(query=query, text=text))
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
            r = self._ask(self.MAP_TEMPLATE.format(query=query, text=chunk))
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
            budget_chars = self._budget_chars(self.MERGE_TEMPLATE, query)
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
            r = self._ask(self.MERGE_TEMPLATE.format(query=query, text=joined))
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
                self.STUFF_TEMPLATE.format(query=query, text=chunk)
                if answer is None
                else self.REFINE_TEMPLATE.format(query=query, answer=answer, text=chunk)
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
        return self._llm.complete(
            prompt, system=self._system,
            max_completion_tokens=self._max_answer_tokens,
        )

    def _learn(self, exc: ContextWindowExceeded) -> None:
        """Shrink the working budget from what a failure just taught.

        Half of the backend's named limit when it named one -- the limit covers prompt
        *and* answer, and template plus answer need their room -- else half of what was
        tried. Kept on the instance: the next chunk, and the next document through this
        summarizer, start from reality instead of the default guess.
        """
        learned = max(256, (exc.limit // 2) if exc.limit else (self._chunk_tokens // 2))
        self._chunk_tokens = min(self._chunk_tokens, learned)

    def _split(self, text: str, query: str) -> list[str]:
        """Pack paragraphs into chunks that fit the working budget."""
        max_chars = self._budget_chars(self.MAP_TEMPLATE, query)
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
        """How many characters of payload fit one call, after template and headroom."""
        skeleton = template.format(query=query, text="", answer="")
        usable = max(256, self._chunk_tokens - estimate_tokens(
            skeleton, self._chars_per_token) - 64)
        return int(usable * self._chars_per_token)

    @staticmethod
    def _is_no_content(text: str) -> bool:
        t = text.strip()
        # Lenient on purpose: models decorate the sentinel ("NO RELEVANT CONTENT."),
        # and an empty answer means the same thing.
        return not t or (NO_CONTENT in t.upper() and len(t) <= len(NO_CONTENT) + 24)

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
        return TokenUsage(prompt=total("prompt"), completion=total("completion"),
                          total=total("total"), reasoning=total("reasoning"),
                          cached=total("cached"))
