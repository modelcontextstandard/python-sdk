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
import logging
import re
from typing import Any, Callable

from mcs.adapter.http import HttpAdapter
from mcs.types.llm import (ContextWindowExceeded, LLMError, LLMResponse,
                           ModelInfo, ModelInfoProvider, TokenUsage)

logger = logging.getLogger(__name__)

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
#: side by side in ``create()`` and leaves the choice to the caller, and so do we. The
#: one exception is *knowledge*, not probing: with a ``model_info`` catalogue injected
#: and no explicit choice, the spelling is derived from what the catalogue states (see
#: ``_field_from_knowledge``).
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
        ``"max_tokens"``; OpenAI's reasoning models reject that name outright and want
        ``"max_completion_tokens"``. There is no name both accept, and the official SDK
        settles it the same way this parameter does: ``create()`` exposes both
        spellings side by side and choosing is the caller's job -- no detection, no
        hidden retry. Get it wrong and the backend's 400 names the right field; this
        adapter appends where to put it.

        Left unset (``None``), the adapter derives the spelling from **knowledge**
        when a *model_info* provider was injected: a reasoning model under the
        ``openai`` provider takes ``"max_completion_tokens"``, everything else the
        ``"max_tokens"`` default. That is data application, not a heuristic -- the
        catalogue states reasoning and provider, and the one measured rejection is
        OpenAI's. Resolved once, lazily, on the first call that sends a budget; an
        explicit value always wins and skips the lookup entirely.
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
    model_info :
        A :class:`~mcs.types.llm.ModelInfoProvider` -- **knowledge** to fall back on
        where the endpoint states nothing (see :mod:`mcs.adapter.llm.info` for the
        catalogue implementations). ``describe()`` asks the endpoint first and lets
        this provider fill only the fields that stayed unknown: a statement is ground
        truth for this connection, knowledge is maintained data that may lag it.
        Optional and never a silent default -- without it, ``describe()`` relays the
        endpoint alone, exactly as before.
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
        max_completion_tokens_field: str | None = None,
        extra_body: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
        timeout: int = 120,
        is_overflow: Callable[[int, str, str], bool] | None = None,
        model_info: ModelInfoProvider | None = None,
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
        self._model_info = model_info
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        headers.update(extra_headers or {})
        self._http = _http or HttpAdapter(default_headers=headers, timeout=timeout)
        # With an injected transport the headers travel per request instead, so its own
        # defaults (a proxy's, an application's) survive rather than being replaced.
        self._extra_headers = {} if _http is None else headers

    # -- LLMPort ---------------------------------------------------------------

    #: Field names under which an enriched /v1/models entry states its window --
    #: vLLM (max_model_len), Groq (context_window), Together (context_length),
    #: Mistral (max_context_length), gateways (max_input_tokens). The plain OpenAI
    #: shape has none of them (measured: four bookkeeping fields, and alias ids like
    #: gpt-5.6 are not even resolved there).
    _INFO_WINDOW_KEYS = ("context_window", "max_model_len", "context_length",
                         "max_context_length", "max_input_tokens")
    _INFO_OUTPUT_KEYS = ("max_output_tokens", "max_completion_tokens")

    def describe(self) -> ModelInfo | None:
        """Ask the endpoint about the model; relay what it states (``LLMPort.describe``).

        Two inquiries, both over the **injected** transport -- the MCS promise that
        every byte travels through the client's adapter holds here too:

        1. ``GET {base}/models/{id}`` -- the route every OpenAI-shaped server has.
           Enriched servers (vLLM, Groq, Mistral, gateways) put the window right
           there; the plain shape answers bookkeeping only.
        2. When no window surfaced and the base URL has a ``/v1`` root, Ollama's
           native ``POST /api/show`` on the same server -- rich: capabilities
           (``tools``, ``thinking``, ``vision``, ``audio``) and the architecture's
           context length. Stated, not guaranteed: measured, 262 144 for a model
           served at ``num_ctx`` 32 768 -- the consumer's clip detector stays the net.

        Then, when the adapter was constructed with a *model_info* provider,
        **knowledge** fills whatever the endpoint left unknown -- field by field,
        statement first: what this connection's backend said about itself outranks
        what a catalogue remembers about the model family.

        Failures are the ``None``-shaped answer, never exceptions: this is an
        inquiry, and every caller needs the unknown path anyway.
        """
        info: dict[str, Any] = {}
        meta: dict[str, Any] = {}
        self._describe_models_endpoint(info, meta)
        if info.get("context_window") is None:
            self._describe_ollama_show(info, meta)
        self._describe_knowledge(info, meta)
        if not meta:
            return None
        return ModelInfo(
            context_window=info.get("context_window"),
            max_output_tokens=info.get("max_output_tokens"),
            supports_function_calling=info.get("supports_function_calling"),
            supports_reasoning=info.get("supports_reasoning"),
            input_modalities=info.get("input_modalities"),
            output_modalities=info.get("output_modalities"),
            meta=meta,
        )

    def _describe_models_endpoint(self, info: dict, meta: dict) -> None:
        try:
            resp = self._http.request(
                "GET", f"{self.base_url}/models/{self.model}",
                headers=self._extra_headers or None, timeout=self.timeout,
            )
            if resp.status_code >= 400:
                return
            data = json.loads(resp.text)
        except Exception:  # noqa: BLE001 -- an inquiry; silence IS the answer
            logger.debug("describe: models endpoint yielded nothing", exc_info=True)
            return
        if not isinstance(data, dict):
            return
        if isinstance(data.get("data"), dict):
            # A gateway envelope, {"data": {...}} -- OpenRouter's shape. The spec
            # object is flat, and its "data" is only ever the LIST route's array,
            # so unwrapping a dict cannot misread a spec answer.
            data = data["data"]
        meta["models_endpoint"] = data
        for key in self._INFO_WINDOW_KEYS:
            if isinstance(data.get(key), int):
                info.setdefault("context_window", data[key])
                break
        for key in self._INFO_OUTPUT_KEYS:
            if isinstance(data.get(key), int):
                info.setdefault("max_output_tokens", data[key])
                break
        supported = data.get("supported_parameters")
        if isinstance(supported, list):
            info.setdefault("supports_function_calling", "tools" in supported)
        arch = data.get("architecture")
        if isinstance(arch, dict):
            # OpenRouter-style gateways state both directions explicitly; the older
            # "text+image->text" string is the same statement in one field. Explicit
            # lists win -- setdefault keeps the first (most explicit) answer.
            for field_name in ("input_modalities", "output_modalities"):
                stated = arch.get(field_name)
                if (isinstance(stated, list) and stated
                        and all(isinstance(m, str) for m in stated)):
                    info.setdefault(field_name, tuple(stated))
            legacy = arch.get("modality")
            if isinstance(legacy, str) and "->" in legacy:
                accepts, _, produces = legacy.partition("->")
                info.setdefault("input_modalities",
                                tuple(m for m in accepts.split("+") if m))
                info.setdefault("output_modalities",
                                tuple(m for m in produces.split("+") if m))

    def _describe_ollama_show(self, info: dict, meta: dict) -> None:
        if not self.base_url.endswith("/v1"):
            return
        root = self.base_url[: -len("/v1")]
        try:
            resp = self._http.request(
                "POST", f"{root}/api/show", json_body={"model": self.model},
                headers=self._extra_headers or None, timeout=self.timeout,
            )
            if resp.status_code >= 400:
                return
            data = json.loads(resp.text)
        except Exception:  # noqa: BLE001
            logger.debug("describe: /api/show yielded nothing", exc_info=True)
            return
        if not isinstance(data, dict):
            return
        # Trimmed on purpose: /api/show also carries tensors, the license text and
        # the whole modelfile -- megabytes nobody plans with.
        show: dict[str, Any] = {}
        for key, value in (data.get("model_info") or {}).items():
            if key.endswith(".context_length") and isinstance(value, int):
                info.setdefault("context_window", value)
                show["context_length"] = value
        capabilities = data.get("capabilities")
        if isinstance(capabilities, list):
            show["capabilities"] = capabilities
            info.setdefault("supports_function_calling", "tools" in capabilities)
            info.setdefault("supports_reasoning", "thinking" in capabilities)
            # Ollama names what a model UNDERSTANDS ("vision", "audio" -- measured on
            # gemma4:e4b) without naming a direction. On a completions API those are
            # inputs, and generation is not served here, so output stays text. The
            # raw list rides in meta for the day that changes.
            if "completion" in capabilities:
                accepts = ["text"]
                accepts += [modality for capability, modality
                            in (("vision", "image"), ("audio", "audio"))
                            if capability in capabilities]
                info.setdefault("input_modalities", tuple(accepts))
                info.setdefault("output_modalities", ("text",))
        if isinstance(data.get("details"), dict):
            show["details"] = data["details"]
        if show:
            meta["ollama_show"] = show

    def _describe_knowledge(self, info: dict, meta: dict) -> None:
        """Let an injected catalogue fill the fields the endpoint left unknown."""
        if self._model_info is None:
            return
        try:
            known = self._model_info.describe(self.model)
        except Exception:  # noqa: BLE001 -- a provider must not break the inquiry
            logger.debug("describe: model_info provider raised", exc_info=True)
            return
        if known is None:
            return
        for field_name in ("context_window", "max_output_tokens",
                           "supports_function_calling", "supports_reasoning",
                           "input_modalities", "output_modalities"):
            value = getattr(known, field_name)
            if info.get(field_name) is None and value is not None:
                info[field_name] = value
        # Catalogue sources keep their own meta keys (litellm, models_dev) -- they sit
        # beside the endpoint's, so nothing is overwritten and provenance stays legible.
        meta.update(known.meta)


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
            body[self._resolve_max_tokens_field()] = max_completion_tokens
        body.update(call_kwargs)
        return body

    def _resolve_max_tokens_field(self) -> str:
        """The wire spelling of the budget field -- explicit, derived, or default.

        Resolved once and kept: an explicit constructor value was never ``None`` and
        wins unseen; otherwise knowledge is consulted a single time, on the first call
        that actually sends a budget -- never in the constructor, which must not do
        network I/O.
        """
        if self._max_tokens_field is None:
            self._max_tokens_field = (self._field_from_knowledge()
                                      or DEFAULT_MAX_COMPLETION_TOKENS_FIELD)
        return self._max_tokens_field

    def _field_from_knowledge(self) -> str | None:
        """The one derivation this adapter performs from catalogue knowledge.

        Measured ground: only OpenAI's reasoning models reject ``max_tokens`` --
        reasoning models elsewhere (Ollama's qwen, DeepSeek) accept it fine. So the
        rule needs both facts, and both are data: the catalogue states
        ``supports_reasoning``, and its meta names the provider the model was found
        under (``models_dev.provider`` / ``litellm.litellm_provider``).
        """
        if self._model_info is None:
            return None
        try:
            known = self._model_info.describe(self.model)
        except Exception:  # noqa: BLE001 -- knowledge must not break the call path
            logger.debug("max-tokens field: model_info provider raised", exc_info=True)
            return None
        if known is None or not known.supports_reasoning:
            return None
        sources = known.meta or {}
        models_dev = sources.get("models_dev") or {}
        # Membership, not a pick: one id sits under many namespaces (the first-party
        # provider plus every gateway reselling it -- measured, 18 for gpt-5.5), and
        # the question here is only "does openai serve this id".
        openai_serves = ("openai" in (models_dev.get("providers") or ())
                         or models_dev.get("provider") == "openai"
                         or (sources.get("litellm") or {}).get("litellm_provider") == "openai")
        return "max_completion_tokens" if openai_serves else None

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
