"""An :class:`~mcs.types.llm.LLMPort` over the **Chat Completions** wire format.

One adapter, not three. Chat Completions (``POST /v1/chat/completions``) is the shape
practically everything speaks: OpenAI itself, Ollama, vLLM, LM Studio and llama.cpp --
the local, cheap models a summarizer actually wants -- plus Groq, Together, OpenRouter,
DeepSeek, Mistral, and the compatibility endpoints of the big vendors.

The sibling formats (``/v1/responses``, ``/v1/messages``) differ because of tool calls,
streaming and thinking blocks. This port has none of those: text in, answer out. Building
three request builders and three auth schemes for identical output would be ballast, and
a client whose model is reachable *only* natively can satisfy
:class:`~mcs.types.llm.LLMPort` directly in a few lines instead.

**Transport only, and stateless.** No context window, no tokenizer, no remembered limits:
those describe the model, not the connection, and an adapter answering for them would be
guessing on behalf of whoever chose the model. What it does instead is *report what the
backend measured* -- the ``usage`` block that comes back with every call -- and translate
the one failure a caller can act on into a type. Planning belongs to the planner.

Transport is :class:`~mcs.adapter.http.HttpAdapter` -- the one MCS already has -- so this
package adds **no** new runtime dependency beyond it.
"""

from __future__ import annotations

import json
import re
from typing import Any, Callable

from mcs.adapter.http import HttpAdapter
from mcs.types.llm import ContextWindowExceeded, LLMError, LLMResponse, TokenUsage

DEFAULT_BASE_URL = "https://api.openai.com/v1"

#: Statuses on which an overflow is even *possible*. There is no status code that means
#: "too long" -- everyone uses 400, which equally covers a bad model name or a malformed
#: parameter, so the status can never confirm an overflow. It can rule one out, though,
#: and that is worth doing: a rate limit is 429 and OpenAI phrases it in *tokens*
#: ("Limit: 30000 tokens per min"). Without this gate a phrase match could turn a
#: wait-and-retry into a split-and-retry, against a wall that has nothing to do with size.
_OVERFLOW_STATUSES = frozenset({400, 413, 422})

#: Machine-readable error codes meaning "the request did not fit".
#: Checked first, because a code is stable where a sentence is not. Only OpenAI and its
#: close clones send one -- llama.cpp, for instance, sends prose and nothing else.
_OVERFLOW_CODES = frozenset({"context_length_exceeded", "string_above_max_length"})

#: Fallback signals, for the majority of backends that send no code.
#:
#: Matching on prose is unlovely, and it is also the state of the art: there is no
#: standard field for this, so every consumer either does it or misses overflows (see
#: openclaw#64180, "context overflow not detected for llama.cpp server provider"). Doing
#: it here means it happens *once*, and a backend we have not met only ever needs a line
#: added -- or, without touching MCS at all, an ``is_overflow`` predicate at construction.
_OVERFLOW_PHRASES = (
    "maximum context length",         # OpenAI, vLLM
    "context length exceeded",
    "available context size",         # llama.cpp server
    "context size",
    "prompt is too long",             # Messages-compatible endpoints
    "maximum input length",
    "reduce the length",
    "exceeds the maximum",
)

#: Patterns that recover the real numbers from an overflow message. Worth the effort:
#: nothing reports a window up front, so the failure is often the first and only place a
#: backend states its real budget.
_LIMIT_PATTERNS = (
    # "This model's maximum context length is 8192 tokens. However, you requested 9001..."
    (re.compile(r"maximum context length is (\d+)"), re.compile(r"you requested (\d+)")),
    # "prompt is too long: 250000 tokens > 200000 maximum"
    (re.compile(r"> ?(\d+) maximum"), re.compile(r": ?(\d+) tokens")),
)

#: Default wire spelling for the answer budget the port calls ``max_completion_tokens``.
#: Deliberately the *older* name: local and older servers know only ``max_tokens``, while
#: OpenAI's reasoning models reject it and want ``max_completion_tokens`` instead. There
#: is no name both understand, so this is a setting -- the ``max_completion_tokens_field``
#: constructor argument -- and never a probe: the official SDK exposes both spellings
#: side by side in ``create()`` and leaves the choice to the caller, and so do we.
DEFAULT_MAX_COMPLETION_TOKENS_FIELD = "max_tokens"

#: Where a backend may put the model's thinking. ``reasoning_content`` is what LiteLLM
#: normalises to (and DeepSeek sends natively), ``reasoning`` is Ollama's. **Neither is in
#: the OpenAPI spec** -- the specification's ``ChatCompletionResponseMessage`` knows only
#: ``content, refusal, tool_calls, annotations, role, function_call, audio``. So these are
#: vendor extensions, read opportunistically and never required.
_REASONING_KEYS = ("reasoning_content", "reasoning")

#: Top-level response fields the spec defines beside ``choices`` and ``usage``. Kept
#: whole in ``meta`` rather than promoted: useful for tracing and support tickets,
#: irrelevant to planning the next call.
_RESPONSE_EXTRAS = ("id", "created", "object", "system_fingerprint", "service_tier")

#: Usage field names, in the order they are tried. The first pair is the Chat Completions
#: standard; the second is Ollama's native wording, which leaks through some deployments
#: (openclaw#53448 -- "incorrect context usage due to field name mismatch"). Reading both
#: is three lines here and spares every consumer the same discovery.
_USAGE_KEYS = (
    ("prompt_tokens", "completion_tokens", "total_tokens"),
    ("prompt_eval_count", "eval_count", None),
)


def _looks_like_overflow(status: int, message: str, code: str) -> bool:
    """The default detector: did this failure mean "your request did not fit"?

    Three steps, in decreasing reliability. The status only ever *excludes* -- it cannot
    confirm, because 400 is what everyone sends for everything. Then a machine-readable
    code, if the backend sent one. Then, reluctantly, the wording.
    """
    if status not in _OVERFLOW_STATUSES:
        return False
    if code in _OVERFLOW_CODES:
        return True
    haystack = message.lower()
    return any(phrase in haystack for phrase in _OVERFLOW_PHRASES)


class CompletionLLMAdapter:
    """Call a Chat Completions endpoint; satisfy :class:`~mcs.types.llm.LLMPort`.

    Parameters
    ----------
    model :
        Model identifier as the endpoint expects it (``"gpt-4o-mini"``, ``"qwen3:8b"``).
    base_url :
        Root of the API, **without** ``/chat/completions``. Defaults to OpenAI; point it
        at ``http://localhost:11434/v1`` for Ollama, and so on.
    api_key :
        Sent as ``Authorization: Bearer``. Optional -- local servers usually want none.
    temperature :
        Passed through when set. A *construction* detail rather than a per-call one: it
        describes how this adapter talks to its backend, not what a caller wants.

        Left unset by default, and not only for tidiness: OpenAI's reasoning models
        reject every value but their default (``400``, *"'temperature' does not support 0
        with this model"*). Sending nothing works everywhere; sending 0 for
        reproducibility works on local servers and fails on GPT-5.

        A client that genuinely needs two temperatures -- extraction and creative
        rewriting, say -- constructs two adapters: they are stateless and can share one
        ``_http``. That is the same move as LangChain's ``bind()`` or a second
        LlamaIndex ``OpenAI(...)``, without the mutable configuration layer.
    reasoning_effort :
        How hard the model may think, where the backend has the notion. Worth a named
        parameter rather than leaving it to *extra_body*, because it moves cost and
        latency by a large factor: measured on gpt-5.5 for a one-word question,
        ``"none"`` produced 0 reasoning tokens and ``"xhigh"`` produced 45.

        **Which values work is per model**, not universal. OpenAI documents
        ``none | minimal | low | medium | high | xhigh | max`` and adds that "supported
        values are model-dependent"; gpt-5.5 and gpt-5.6 on Chat Completions accept
        ``none, low, medium, high, xhigh`` and reject ``minimal`` and ``max``. Passed
        through untouched, because only the backend can be authoritative -- and it says
        so, listing its accepted values in the error.

        Note also that OpenAI considers reasoning better served by the Responses API:
        with ``reasoning_effort`` set, GPT-5.4+ refuse tool calls on Chat Completions
        entirely. This port sends no tools, so that limit does not apply here -- but it
        is the reason a ``mcs-adapter-llm-response`` sibling is more than symmetry.
    max_completion_tokens_field :
        **The wire field name** for the answer budget the port calls
        ``max_completion_tokens``. Older and local servers understand only
        ``"max_tokens"`` (the default); OpenAI's reasoning models reject that name
        outright and want ``"max_completion_tokens"``. There is no name both accept, and
        the official SDK settles it the same way this parameter does: ``create()``
        exposes both spellings side by side and choosing is the caller's job -- no
        detection, no hidden retry. Get it wrong and the backend's 400 names the right
        field; this adapter appends where to put it.
    extra_body :
        Construction-time body defaults, merged over the named values (so they can
        override them); per-call ``complete(**kwargs)`` wins over both. Together with
        *extra_headers* this is the escape hatch that keeps the named parameters few:
        the spec's request object has 28 fields (``verbosity``, ``seed``,
        ``response_format``, ``logit_bias``, ...) and backends add their own
        (``num_ctx``, ``top_k``). Naming them all here would be a second, worse copy of
        a specification that changes without us.
    extra_headers :
        Sent with every request -- for gateways that want more than a bearer token
        (OpenRouter's ``HTTP-Referer`` / ``X-Title``, a tenant or routing header).
    timeout :
        Per-request timeout in seconds. Higher than the HTTP default on purpose: a
        summarization prompt over a long chunk is not a web request.
    is_overflow :
        ``(status, message, code) -> bool``, replacing the built-in detection. There is no
        standard way for a backend to say "too long" (see :data:`_OVERFLOW_PHRASES`), so a
        server we have never met may word it in a way this adapter misses. Rather than
        wait for a release, teach it here.
    _http :
        Injected transport (DPI). Supply one to share connection settings, a proxy or
        Basic-Auth with the rest of an application -- or a fake, in tests.
    """

    def __init__(
        self,
        model: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        api_key: str | None = None,
        temperature: float | None = None,
        reasoning_effort: str | None = None,
        max_completion_tokens_field: str = DEFAULT_MAX_COMPLETION_TOKENS_FIELD,
        extra_body: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
        timeout: int = 120,
        is_overflow: Callable[[int, str, str], bool] | None = None,
        _http: HttpAdapter | None = None,
    ) -> None:
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.temperature = temperature
        self.reasoning_effort = reasoning_effort
        self.extra_body = dict(extra_body or {})
        self.timeout = timeout
        self._is_overflow = is_overflow or _looks_like_overflow
        self._max_tokens_field = max_completion_tokens_field
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        headers.update(extra_headers or {})
        self._http = _http or HttpAdapter(default_headers=headers, timeout=timeout)
        # With an injected transport the headers travel per request instead, so its own
        # defaults (a proxy's, an application's) survive rather than being replaced.
        self._extra_headers = {} if _http is None else headers

    # -- LLMPort ---------------------------------------------------------------

    def complete(
        self,
        prompt: str,
        *,
        system: str | None = None,
        max_completion_tokens: int | None = None,
        **kwargs: Any,
    ) -> LLMResponse:
        """Send one request and return the answer with what it measurably cost.

        The body is assembled construction-first, call-last -- the LangChain-constructor
        / LlamaIndex-``complete(**kwargs)`` blend: named construction values, then
        ``extra_body``, then the ``max_completion_tokens`` budget (mapped onto the
        configured wire field), then per-call *kwargs*. Later wins, so a call can
        override anything the construction set. Nothing is validated or renamed on the
        way through -- except that one budget field; the backend is authoritative.
        """
        resp = self._post(self._build_body(prompt, system, max_completion_tokens, kwargs))
        if resp.status_code >= 400:
            raise self._translate_error(resp.status_code, resp.text)
        return self._response_from(resp.text)

    # -- building and sending --------------------------------------------------

    def _build_body(
        self, prompt: str, system: str | None, max_completion_tokens: int | None,
        call_kwargs: dict[str, Any],
    ) -> dict[str, Any]:
        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        # Precedence, least to strongest: named construction values, extra_body, the
        # portable budget (a *call* argument, hence above construction), per-call kwargs.
        body: dict[str, Any] = {"model": self.model, "messages": messages}
        if self.temperature is not None:
            body["temperature"] = self.temperature
        if self.reasoning_effort is not None:
            body["reasoning_effort"] = self.reasoning_effort
        body.update(self.extra_body)
        if max_completion_tokens is not None:
            body[self._max_tokens_field] = max_completion_tokens
        body.update(call_kwargs)
        return body

    def _post(self, body: dict[str, Any]):
        return self._http.request(
            "POST",
            f"{self.base_url}/chat/completions",
            json_body=body,
            headers=self._extra_headers or None,
            timeout=self.timeout,
        )

    def _field_hint(self, code: str, param: str) -> str:
        """One actionable sentence when the backend rejected our max-tokens field name.

        The backend's message already names the right field; this adds *where to put
        it*. Deliberately instead of resending corrected -- no hidden second request, no
        state, the developer flips one constructor argument. The official SDK draws the
        same line: both spellings sit side by side in ``create()``, and choosing is the
        caller's job.
        """
        if code != "unsupported_parameter" or param != self._max_tokens_field:
            return ""
        other = {"max_tokens": "max_completion_tokens",
                 "max_completion_tokens": "max_tokens"}.get(param)
        if other is None:
            return ""
        return f" (construct this adapter with max_completion_tokens_field={other!r})"

    # -- reading the answer ----------------------------------------------------

    @classmethod
    def _response_from(cls, payload: str) -> LLMResponse:
        """Build an :class:`LLMResponse` from a Chat Completions body."""
        try:
            data = json.loads(payload)
        except ValueError as exc:
            raise LLMError(f"Response was not JSON: {payload[:200]}") from exc

        choices = data.get("choices")
        if not isinstance(choices, list) or not choices:
            raise LLMError(f"Response carried no choices: {payload[:200]}")
        choice = choices[0] or {}
        message = choice.get("message") or {}
        content = message.get("content")
        if content is None:
            # An empty *string* is a legitimate answer and passes through; a missing or
            # null content is not -- the model produced something other than text, which
            # this port has no way to represent. A *refusal* is the one case where the
            # backend says why, and the spec gives it its own field: carry that reason
            # out rather than reporting a blank failure.
            refusal = message.get("refusal")
            if refusal:
                raise LLMError(f"The model refused: {refusal}")
            raise LLMError(f"Response carried no text content: {payload[:200]}")

        meta: dict[str, Any] = {}
        if isinstance(data.get("usage"), dict):
            # Verbatim, so a breakdown we did not anticipate is not lost.
            meta["usage"] = data["usage"]
        extras = {k: data[k] for k in _RESPONSE_EXTRAS if data.get(k) is not None}
        if extras:
            meta["extras"] = extras
        # Vendor territory, but real and worth keeping: the model's thinking is text that
        # cost completion tokens and appears nowhere else. Without it, a caller staring at
        # an empty answer cannot see where its budget went.
        for key in _REASONING_KEYS:
            if message.get(key):
                meta["reasoning_text"] = message[key]
                break
        if message.get("thinking_blocks"):      # Anthropic's shape, via compat layers
            meta["thinking_blocks"] = message["thinking_blocks"]

        return LLMResponse(
            text=content,
            usage=cls._usage_from(data.get("usage")),
            finish_reason=choice.get("finish_reason"),
            model=data.get("model"),
            meta=meta,
        )

    @staticmethod
    def _usage_from(usage: Any) -> TokenUsage:
        """Read the measured token counts, under whichever names the backend used."""
        if not isinstance(usage, dict):
            return TokenUsage()

        def _int(container: Any, key: str | None) -> int | None:
            if not key or not isinstance(container, dict):
                return None
            value = container.get(key)
            return value if isinstance(value, int) else None

        for prompt_key, completion_key, total_key in _USAGE_KEYS:
            if prompt_key not in usage and completion_key not in usage:
                continue
            return TokenUsage(
                prompt=_int(usage, prompt_key),
                completion=_int(usage, completion_key),
                total=_int(usage, total_key),
                # The breakdowns are OpenAI's shape and simply absent elsewhere -- which
                # is why they are Optional rather than defaulted to zero: "not reported"
                # and "none spent" are different facts.
                reasoning=_int(usage.get("completion_tokens_details"), "reasoning_tokens"),
                cached=_int(usage.get("prompt_tokens_details"), "cached_tokens"),
            )
        return TokenUsage()

    # -- translating the failure -----------------------------------------------

    def _translate_error(self, status: int, payload: str) -> LLMError:
        """Turn a backend error into the one type callers can act on -- or a plain one."""
        message, code, param = self._error_fields(payload)
        if not self._is_overflow(status, message, code):
            hint = self._field_hint(code, param)
            return LLMError(f"HTTP {status} from {self.base_url}: "
                            f"{message or payload[:200]}{hint}")
        limit, requested = self._limits_in(message)
        return ContextWindowExceeded(message or "Context window exceeded.",
                                     limit=limit, requested=requested)

    @staticmethod
    def _error_fields(payload: str) -> tuple[str, str, str]:
        """``(message, code, param)`` from an error body, tolerating every shape seen.

        *param* names the offending field where the backend says so -- the machine-readable
        half of an error, and the only part worth branching on when one exists.
        """
        try:
            data = json.loads(payload)
        except ValueError:
            return payload[:500], "", ""
        error = data.get("error", data)
        if isinstance(error, str):            # some servers send {"error": "text"}
            return error, "", ""
        if not isinstance(error, dict):
            return payload[:500], "", ""
        message = error.get("message") or data.get("detail") or ""
        return (
            message if isinstance(message, str) else str(message),
            str(error.get("code") or ""),
            str(error.get("param") or ""),
        )

    @staticmethod
    def _limits_in(message: str) -> tuple[int | None, int | None]:
        """Recover ``(limit, requested)`` from an overflow message, when it states them."""
        for limit_re, requested_re in _LIMIT_PATTERNS:
            limit_hit = limit_re.search(message)
            if not limit_hit:
                continue
            requested_hit = requested_re.search(message)
            return (
                int(limit_hit.group(1)),
                int(requested_hit.group(1)) if requested_hit else None,
            )
        return None, None
