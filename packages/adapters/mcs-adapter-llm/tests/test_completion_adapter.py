"""Chat Completions adapter: request shape, response reading, error translation.

Every test runs offline against an injected fake transport (``_http``) -- which is what
the DPI slot is for. Nothing here needs a key, a network or a model.
"""

from __future__ import annotations

import json

import pytest

from mcs.adapter.llm.completion import CompletionLLMAdapter
from mcs.types.http import HttpResponse
from mcs.types.llm import ContextWindowExceeded, LLMError, LLMPort, ModelInfo


class FakeHttp:
    """Records the outgoing request and replays a canned response."""

    def __init__(self, status: int = 200, payload: object | str | None = None) -> None:
        self.status = status
        self.payload = payload if payload is not None else _answer("ok")
        self.calls: list[dict] = []

    def request(self, method, url, *, params=None, json_body=None, headers=None, timeout=None):
        self.calls.append({"method": method, "url": url, "json_body": json_body,
                           "headers": headers, "timeout": timeout})
        text = self.payload if isinstance(self.payload, str) else json.dumps(self.payload)
        return HttpResponse(status_code=self.status, text=text)

    @property
    def last(self) -> dict:
        return self.calls[-1]


def _answer(content: str | None, **extra) -> dict:
    choice: dict = {"message": {"role": "assistant", "content": content}}
    choice.update(extra.pop("choice", {}))
    body: dict = {"choices": [choice]}
    body.update(extra)
    return body


def _error(message: str, code: str | None = None) -> dict:
    err: dict = {"message": message}
    if code:
        err["code"] = code
    return {"error": err}


def _adapter(http: FakeHttp, **kw) -> CompletionLLMAdapter:
    return CompletionLLMAdapter("test-model", _http=http, **kw)


class TestContract:

    def test_satisfies_the_port(self):
        assert isinstance(_adapter(FakeHttp()), LLMPort)

    def test_carries_no_model_metadata(self):
        """A context window and a tokenizer describe the *model*, not the connection to
        it. An adapter answering for them would be guessing on behalf of whoever chose
        the model -- so it reports what the backend measured instead."""
        adapter = _adapter(FakeHttp())
        assert not hasattr(adapter, "context_window")
        assert not hasattr(adapter, "count_tokens")


class TestRequest:

    def test_posts_to_chat_completions(self):
        http = FakeHttp()
        _adapter(http, base_url="http://localhost:11434/v1/").complete("hi")
        assert http.last["method"] == "POST"
        assert http.last["url"] == "http://localhost:11434/v1/chat/completions"

    def test_user_message_only_without_system(self):
        http = FakeHttp()
        _adapter(http).complete("summarise this")
        assert http.last["json_body"]["messages"] == [
            {"role": "user", "content": "summarise this"}
        ]

    def test_system_precedes_the_prompt(self):
        http = FakeHttp()
        _adapter(http).complete("the text", system="Answer only from the text.")
        assert [m["role"] for m in http.last["json_body"]["messages"]] == ["system", "user"]

    def test_optional_fields_are_omitted_when_unset(self):
        http = FakeHttp()
        _adapter(http).complete("hi")
        body = http.last["json_body"]
        assert "max_tokens" not in body and "temperature" not in body

    def test_max_tokens_and_temperature_are_passed(self):
        http = FakeHttp()
        _adapter(http, temperature=0.0).complete("hi", max_completion_tokens=256)
        assert http.last["json_body"]["max_tokens"] == 256
        assert http.last["json_body"]["temperature"] == 0.0

    def test_extra_body_reaches_the_backend(self):
        """Backend-specific knobs have no place in the port, but must stay reachable."""
        http = FakeHttp()
        _adapter(http, extra_body={"num_ctx": 32768}).complete("hi")
        assert http.last["json_body"]["num_ctx"] == 32768

    def test_reasoning_effort_is_passed_through_unvalidated(self):
        """Which values a model accepts is the model's business -- OpenAI documents seven
        and says the set is model-dependent, and the backend names its own in the error.
        Validating here would only go stale."""
        http = FakeHttp()
        _adapter(http, reasoning_effort="xhigh").complete("hi")
        assert http.last["json_body"]["reasoning_effort"] == "xhigh"

    def test_reasoning_effort_is_omitted_when_unset(self):
        http = FakeHttp()
        _adapter(http).complete("hi")
        assert "reasoning_effort" not in http.last["json_body"]

    def test_extra_body_can_override_what_the_adapter_set(self):
        """The spec's request object has 28 fields and backends add their own. Naming
        them all would be a second, worse copy of a specification that changes without
        us -- so the escape hatch has the last word."""
        http = FakeHttp()
        _adapter(http, temperature=0.7, extra_body={"temperature": 1.0}).complete("hi")
        assert http.last["json_body"]["temperature"] == 1.0

    def test_extra_headers_reach_the_backend(self):
        """Gateways want more than a bearer token -- OpenRouter's HTTP-Referer, a tenant
        header, a routing hint."""
        http = FakeHttp()
        _adapter(http, api_key="k", extra_headers={"X-Title": "MCS"}).complete("hi")
        assert http.last["headers"]["X-Title"] == "MCS"
        assert http.last["headers"]["Authorization"] == "Bearer k"


class TestPerCallKwargs:
    """The LangChain-constructor / LlamaIndex-complete blend: construction sets the
    defaults, ``complete(**kwargs)`` passes anything else through verbatim, and the call
    wins. Nothing is validated or renamed -- the developer wired the backend in and
    knows what it takes; the backend is authoritative."""

    def test_kwargs_are_passed_through_verbatim(self):
        http = FakeHttp()
        _adapter(http).complete("hi", response_format={"type": "json_object"},
                                stop=["\n\n"])
        assert http.last["json_body"]["response_format"] == {"type": "json_object"}
        assert http.last["json_body"]["stop"] == ["\n\n"]

    def test_the_call_wins_over_the_constructor(self):
        http = FakeHttp()
        _adapter(http, temperature=0.2).complete("hi", temperature=1.0)
        assert http.last["json_body"]["temperature"] == 1.0

    def test_the_call_wins_over_extra_body(self):
        http = FakeHttp()
        _adapter(http, extra_body={"seed": 7}).complete("hi", seed=42)
        assert http.last["json_body"]["seed"] == 42

    def test_the_call_wins_over_the_mapped_budget(self):
        """Whoever names the wire field explicitly means it -- even over the portable
        ``max_completion_tokens`` mapping of the same call. Here the default field is
        ``max_tokens``: the portable budget maps 64 onto it, the verbatim kwarg then
        overrides the very same key."""
        http = FakeHttp()
        _adapter(http).complete("hi", max_completion_tokens=64, max_tokens=128)
        assert http.last["json_body"]["max_tokens"] == 128

    def test_no_kwargs_means_construction_defaults_untouched(self):
        """The common case: construct once, call plainly."""
        http = FakeHttp()
        _adapter(http, temperature=0.2, extra_body={"seed": 7}).complete("hi")
        assert http.last["json_body"]["temperature"] == 0.2
        assert http.last["json_body"]["seed"] == 7


class TestMaxTokensField:
    """There is no field name every Chat Completions backend accepts: older servers know
    only ``max_tokens``, OpenAI's reasoning models reject it by name in favour of
    ``max_completion_tokens`` (measured against gpt-5.5 and gpt-5.6, both 400).

    The adapter does NOT probe or auto-switch. The official SDK is the precedent: its
    ``create()`` exposes both spellings side by side and choosing is the caller's job.
    Ours is one constructor knob, and a wrong choice fails loudly with the fix named."""

    REJECTION = {"error": {"message": "Unsupported parameter: 'max_tokens' is not "
                                      "supported with this model. Use "
                                      "'max_completion_tokens' instead.",
                           "type": "invalid_request_error",
                           "code": "unsupported_parameter", "param": "max_tokens"}}

    def test_default_field_is_max_tokens(self):
        """The broadly-supported spelling -- local and older servers know only this."""
        http = FakeHttp()
        _adapter(http).complete("hi", max_completion_tokens=64)
        assert http.last["json_body"]["max_tokens"] == 64

    def test_configured_field_is_used_verbatim(self):
        http = FakeHttp()
        _adapter(http, max_completion_tokens_field="max_completion_tokens").complete("hi", max_completion_tokens=64)
        assert http.last["json_body"]["max_completion_tokens"] == 64
        assert "max_tokens" not in http.last["json_body"]

    def test_rejection_is_not_retried_and_names_the_constructor_fix(self):
        """One request, one error -- no hidden probe, no state. The error carries the
        backend's own instruction plus where to apply it, so the developer flips one
        argument at development time instead of paying a probing call in production."""
        http = FakeHttp(400, self.REJECTION)
        with pytest.raises(LLMError) as exc:
            _adapter(http).complete("hi", max_completion_tokens=64)
        assert len(http.calls) == 1
        assert "max_completion_tokens" in str(exc.value)     # the backend's instruction
        assert "construct this adapter" in str(exc.value)    # ...and our pointer

    def test_reverse_rejection_hints_the_other_way(self):
        http = FakeHttp(400, {"error": {"message": "Unknown parameter: "
                                        "'max_completion_tokens'.",
                              "code": "unsupported_parameter",
                              "param": "max_completion_tokens"}})
        with pytest.raises(LLMError, match="max_completion_tokens_field='max_tokens'"):
            _adapter(http, max_completion_tokens_field="max_completion_tokens").complete(
                "hi", max_completion_tokens=64)

    def test_an_unrelated_rejection_gets_no_hint(self):
        """Only the exact code+param pair earns the hint. Anything else is a real
        failure and must surface untouched."""
        http = FakeHttp(400, {"error": {"message": "no such model", "code":
                                        "model_not_found", "param": "model"}})
        with pytest.raises(LLMError, match="no such model") as exc:
            _adapter(http).complete("hi", max_completion_tokens=64)
        assert "construct this adapter" not in str(exc.value)


class TestResponse:

    def test_returns_the_assistant_text(self):
        assert _adapter(FakeHttp(payload=_answer("Three repos."))).complete("q").text == "Three repos."

    def test_empty_string_is_a_legitimate_answer(self):
        assert _adapter(FakeHttp(payload=_answer(""))).complete("q").text == ""

    def test_reports_measured_usage(self):
        """The counts come from the model's own tokenizer -- exact where an estimate is
        not, and free with every call."""
        payload = _answer("ok", usage={"prompt_tokens": 52, "completion_tokens": 8,
                                       "total_tokens": 60})
        usage = _adapter(FakeHttp(payload=payload)).complete("q").usage
        assert (usage.input, usage.output, usage.total) == (52, 8, 60)

    def test_unreported_usage_is_none_not_zero(self):
        """"Not reported" and "none spent" are different facts, and a caller calibrating
        an estimate must skip the first rather than record it as costing nothing."""
        usage = _adapter(FakeHttp(payload=_answer("ok"))).complete("q").usage
        assert usage.input is None and usage.total is None

    def test_reasoning_and_cache_read_breakdowns_are_read(self):
        payload = _answer("ok", usage={
            "prompt_tokens": 100, "completion_tokens": 319, "total_tokens": 419,
            "completion_tokens_details": {"reasoning_tokens": 300},
            "prompt_tokens_details": {"cached_tokens": 64},
        })
        usage = _adapter(FakeHttp(payload=payload)).complete("q").usage
        assert usage.reasoning == 300 and usage.cache_read == 64
        assert usage.cache_write is None       # no such concept on this wire: not 0

    def test_a_gateway_cache_write_count_is_read(self):
        """Not a Chat Completions field -- but gateways speaking this wire over
        Anthropic models surface the write count top-level (LiteLLM proxy), and cost
        accounting needs it: cache writes bill at a premium."""
        payload = _answer("ok", usage={
            "prompt_tokens": 100, "completion_tokens": 8,
            "cache_creation_input_tokens": 90,
        })
        usage = _adapter(FakeHttp(payload=payload)).complete("q").usage
        assert usage.cache_write == 90

    def test_ollama_field_names_are_understood(self):
        payload = _answer("ok", usage={"prompt_eval_count": 52, "eval_count": 8})
        usage = _adapter(FakeHttp(payload=payload)).complete("q").usage
        assert (usage.input, usage.output, usage.total) == (52, 8, None)

    def test_raw_usage_survives_in_meta(self):
        """A breakdown we did not anticipate must not be thrown away."""
        payload = _answer("ok", usage={"prompt_tokens": 1, "surprise_tokens": 7})
        meta = _adapter(FakeHttp(payload=payload)).complete("q").meta
        assert meta["usage"]["surprise_tokens"] == 7

    def test_a_thinking_model_can_spend_its_whole_budget(self):
        """Observed against qwen3 via Ollama: with a modest max_tokens the reasoning
        consumed all of it, leaving content="" and finish_reason="length" -- an empty
        answer and no error at all. `truncated` is the only signal that this happened."""
        payload = _answer("", choice={"finish_reason": "length"},
                          usage={"prompt_tokens": 52, "completion_tokens": 64})
        answer = _adapter(FakeHttp(payload=payload)).complete("q")
        assert answer.text == ""
        assert answer.truncated is True

    def test_null_content_with_reasoning_is_the_thinking_trap_not_an_error(self):
        """Measured on kimi-k3 via OpenRouter: the whole budget spent thinking
        arrives as content: null with 12k characters in `reasoning` -- the same
        trap Ollama spells as content: "". Empty text plus truncated, never an
        exception; the thinking survives in meta."""
        payload = _answer(None, choice={
            "finish_reason": "length",
            "message": {"role": "assistant", "content": None,
                        "reasoning": "Let me think at length..."}})
        answer = _adapter(FakeHttp(payload=payload)).complete("q")
        assert answer.text == ""
        assert answer.truncated is True
        assert answer.meta["reasoning_text"] == "Let me think at length..."

    def test_a_complete_answer_is_not_truncated(self):
        payload = _answer("Mimi", choice={"finish_reason": "stop"})
        assert _adapter(FakeHttp(payload=payload)).complete("q").truncated is False

    def test_reasoning_text_is_kept_where_a_backend_exposes_it(self):
        """Non-standard, but it is where the missing budget went -- and nowhere else."""
        payload = _answer("", choice={"message": {"role": "assistant", "content": "",
                                                  "reasoning": "Let me think..."}})
        meta = _adapter(FakeHttp(payload=payload)).complete("q").meta
        assert meta["reasoning_text"] == "Let me think..."

    def test_reasoning_content_is_read_too(self):
        """LiteLLM normalises the model's thinking to `reasoning_content` (DeepSeek sends
        it natively); Ollama calls it `reasoning`. Neither is in the OpenAPI spec, so both
        are read opportunistically."""
        payload = _answer("ok", choice={"message": {"role": "assistant", "content": "ok",
                                                    "reasoning_content": "Hmm..."}})
        assert _adapter(FakeHttp(payload=payload)).complete("q").meta["reasoning_text"] == "Hmm..."

    def test_thinking_blocks_are_kept(self):
        payload = _answer("ok", choice={"message": {"role": "assistant", "content": "ok",
                                                    "thinking_blocks": [{"type": "thinking"}]}})
        meta = _adapter(FakeHttp(payload=payload)).complete("q").meta
        assert meta["thinking_blocks"] == [{"type": "thinking"}]

    def test_spec_level_extras_are_kept_for_tracing(self):
        payload = _answer("ok", id="chatcmpl-604", system_fingerprint="fp_ollama",
                          created=1786037091)
        extras = _adapter(FakeHttp(payload=payload)).complete("q").meta["extras"]
        assert extras["id"] == "chatcmpl-604"
        assert extras["system_fingerprint"] == "fp_ollama"

    def test_a_refusal_says_why(self):
        """`refusal` is a spec field, and the one case where a null content comes with a
        reason. Reporting a blank failure would throw that reason away."""
        payload = _answer(None, choice={"message": {"role": "assistant", "content": None,
                                                    "refusal": "I can't help with that."}})
        with pytest.raises(LLMError, match="refused: I can't help with that"):
            _adapter(FakeHttp(payload=payload)).complete("q")

    def test_reports_the_model_that_answered(self):
        """Not necessarily the one requested -- a gateway may route elsewhere, and a
        caller recording measurements needs to know what it measured."""
        payload = _answer("ok", model="qwen3:4b")
        assert _adapter(FakeHttp(payload=payload)).complete("q").model == "qwen3:4b"

    def test_null_content_fails_rather_than_returning_nothing(self):
        """A tool call or refusal object is not text, and this port cannot carry it --
        better a loud error than an empty summary nobody questions."""
        with pytest.raises(LLMError, match="no text content"):
            _adapter(FakeHttp(payload=_answer(None))).complete("q")

    def test_missing_choices_fails(self):
        with pytest.raises(LLMError, match="no choices"):
            _adapter(FakeHttp(payload={"id": "x"})).complete("q")

    def test_non_json_fails(self):
        with pytest.raises(LLMError, match="not JSON"):
            _adapter(FakeHttp(payload="<html>502 Bad Gateway</html>")).complete("q")


class TestErrorTranslation:
    """The adapter's real job: every backend words 'too long' differently, so it is
    translated once here and consumers branch on a type instead of on prose."""

    OPENAI = ("This model's maximum context length is 8192 tokens. "
              "However, you requested 9001 tokens (8500 in the messages, 501 in the "
              "completion). Please reduce the length of the messages.")
    MESSAGES = "prompt is too long: 250000 tokens > 200000 maximum"

    def test_openai_overflow_carries_both_numbers(self):
        http = FakeHttp(400, _error(self.OPENAI, code="context_length_exceeded"))
        with pytest.raises(ContextWindowExceeded) as exc:
            _adapter(http).complete("q")
        assert exc.value.limit == 8192
        assert exc.value.requested == 9001

    def test_messages_style_overflow_is_recognised_without_a_code(self):
        """No error code, different wording, different vendor -- same type out."""
        http = FakeHttp(400, _error(self.MESSAGES))
        with pytest.raises(ContextWindowExceeded) as exc:
            _adapter(http).complete("q")
        assert exc.value.limit == 200000
        assert exc.value.requested == 250000

    def test_the_discovered_limit_travels_on_the_exception(self):
        """Nothing reports a window up front, so an overflow is often the first and only
        statement of the real budget -- but the adapter does not *keep* it. Remembering
        belongs to whoever is planning the chunks; a transport that cached it would be
        holding state about a model it does not own."""
        http = FakeHttp(400, _error(self.OPENAI, code="context_length_exceeded"))
        adapter = _adapter(http)
        with pytest.raises(ContextWindowExceeded) as exc:
            adapter.complete("q")
        assert exc.value.limit == 8192              # the planner reads it from here
        assert not hasattr(adapter, "context_window")   # ...and the adapter stays clean

    def test_other_failures_stay_plain_errors(self):
        """An auth failure must not look like an overflow -- splitting the input would
        retry forever against a wall that has nothing to do with size."""
        http = FakeHttp(401, _error("Incorrect API key provided", code="invalid_api_key"))
        with pytest.raises(LLMError) as exc:
            _adapter(http).complete("q")
        assert not isinstance(exc.value, ContextWindowExceeded)
        assert "401" in str(exc.value)

    def test_overflow_without_numbers_still_has_the_right_type(self):
        http = FakeHttp(400, _error("Input exceeds the maximum length for this model."))
        with pytest.raises(ContextWindowExceeded) as exc:
            _adapter(http).complete("q")
        assert exc.value.limit is None

    def test_unparseable_error_body_does_not_mask_the_failure(self):
        http = FakeHttp(500, "upstream connect error")
        with pytest.raises(LLMError, match="500"):
            _adapter(http).complete("q")

    def test_llama_cpp_wording_is_recognised(self):
        """llama.cpp sends prose and no code at all -- and it is one of the most common
        servers for exactly the small local models this port exists to reach."""
        http = FakeHttp(400, _error("the request exceeds the available context size, "
                                    "try increasing it"))
        with pytest.raises(ContextWindowExceeded):
            _adapter(http).complete("q")

    def test_a_rate_limit_is_never_read_as_an_overflow(self):
        """429 is phrased in *tokens* too ("Limit: 30000 tokens per min"). Splitting the
        input would retry against a time limit that has nothing to do with size, so the
        status rules the overflow out before any wording is considered."""
        http = FakeHttp(429, _error("Rate limit reached for gpt-4o. Limit: 30000 tokens "
                                    "per min. Please reduce the length or try again later."))
        with pytest.raises(LLMError) as exc:
            _adapter(http).complete("q")
        assert not isinstance(exc.value, ContextWindowExceeded)

    def test_detection_can_be_replaced_for_an_unknown_backend(self):
        """No standard field exists for this, so a server we have never met may word it
        in a way we miss. Teaching the adapter must not require a release."""
        http = FakeHttp(400, _error("PLATZ ZU KLEIN"))
        with pytest.raises(LLMError) as plain:                     # not recognised...
            _adapter(http).complete("q")
        assert not isinstance(plain.value, ContextWindowExceeded)

        adapter = _adapter(http, is_overflow=lambda s, m, c: "PLATZ ZU KLEIN" in m)
        with pytest.raises(ContextWindowExceeded):                 # ...until taught
            adapter.complete("q")


class TestDescribe:
    """describe() relays what the endpoint STATES -- an inquiry over the same injected
    transport, with None as the failure shape. Payload shapes are the measured ones."""

    class SeqHttp:
        """Plays back one canned response per request, in order; 404 when exhausted."""

        def __init__(self, *responses):
            self.responses = list(responses)
            self.calls = []

        def request(self, method, url, *, params=None, json_body=None, headers=None,
                    timeout=None):
            self.calls.append({"method": method, "url": url, "json_body": json_body})
            status, payload = (self.responses.pop(0) if self.responses else (404, {}))
            text = payload if isinstance(payload, str) else json.dumps(payload)
            return HttpResponse(status_code=status, text=text)

    #: Measured: what OpenAI and Ollama's /v1 layer answer -- bookkeeping only.
    MEAGRE = {"id": "test-model", "object": "model", "created": 1, "owned_by": "x"}
    #: Measured: Ollama /api/show for qwen3:4b, plus the bulk fields that must be cut.
    SHOW = {"capabilities": ["completion", "tools", "thinking"],
            "details": {"family": "qwen3"},
            "model_info": {"qwen3.context_length": 262144,
                           "qwen3.embedding_length": 2560},
            "tensors": [{"name": "blk.0"}], "license": "L" * 64, "modelfile": "FROM q"}
    #: Measured: Ollama /api/show for gemma4:e4b -- a model that understands more
    #: than text states it in the same capabilities list.
    SHOW_MULTIMODAL = {"capabilities": ["completion", "vision", "audio", "tools",
                                        "thinking"],
                       "model_info": {"gemma4.context_length": 131072}}
    #: Measured: an OpenRouter-style architecture block -- both directions explicit,
    #: the older "a+b->c" string beside them, order relayed as stated.
    ARCHITECTURE = {"input_modalities": ["file", "image", "text"],
                    "output_modalities": ["image", "text"],
                    "modality": "text+image+file->text+image"}

    def _adapter(self, http, base="http://localhost:11434/v1"):
        return CompletionLLMAdapter("test-model", base_url=base, _http=http)

    def test_an_enriched_models_endpoint_is_enough(self):
        """vLLM-style: the window sits right in /v1/models -- no second inquiry."""
        http = self.SeqHttp((200, {"id": "m", "max_model_len": 40960}))
        info = self._adapter(http).describe()
        assert info.context_window == 40960
        assert len(http.calls) == 1

    def test_a_meagre_shape_falls_through_to_api_show(self):
        http = self.SeqHttp((200, self.MEAGRE), (200, self.SHOW))
        info = self._adapter(http).describe()
        assert info.context_window == 262144
        assert info.supports_function_calling is True
        assert info.supports_reasoning is True
        assert http.calls[1]["url"].endswith("/api/show")
        assert http.calls[1]["json_body"] == {"model": "test-model"}

    def test_a_text_only_model_states_text_only(self):
        """'completion' without 'vision'/'audio' IS a statement: text in, text out --
        ("text",) is different from None (nothing said)."""
        http = self.SeqHttp((200, self.MEAGRE), (200, self.SHOW))
        info = self._adapter(http).describe()
        assert info.input_modalities == ("text",)
        assert info.output_modalities == ("text",)

    def test_understanding_capabilities_become_inputs(self):
        """Ollama names modalities without a direction (measured on gemma4:e4b:
        'vision', 'audio'). On a completions API those are inputs; generation is not
        served here, so output stays text."""
        http = self.SeqHttp((200, self.MEAGRE), (200, self.SHOW_MULTIMODAL))
        info = self._adapter(http).describe()
        assert info.input_modalities == ("text", "image", "audio")
        assert info.output_modalities == ("text",)

    def test_gateway_architecture_states_both_directions(self):
        """OpenRouter-style: explicit lists, relayed verbatim -- including image on
        the OUTPUT side, which no capability mapping could express."""
        http = self.SeqHttp((200, {"id": "m", "context_length": 128000,
                                   "architecture": self.ARCHITECTURE}))
        info = self._adapter(http).describe()
        assert info.input_modalities == ("file", "image", "text")
        assert info.output_modalities == ("image", "text")

    def test_legacy_modality_string_is_the_same_statement(self):
        """Older gateways state 'text+image->text' in one field; parsing it is a
        spelling translation, not a guess."""
        http = self.SeqHttp((200, {"id": "m", "context_length": 128000,
                                   "architecture": {"modality": "text+image->text"}}))
        info = self._adapter(http).describe()
        assert info.input_modalities == ("text", "image")
        assert info.output_modalities == ("text",)

    def test_explicit_lists_win_over_the_legacy_string(self):
        """When both spellings are present the explicit one is the more deliberate
        statement -- the string is only the fallback."""
        arch = {"input_modalities": ["text", "image", "audio"],
                "output_modalities": ["text"],
                "modality": "text+image->text"}
        http = self.SeqHttp((200, {"id": "m", "context_length": 1,
                                   "architecture": arch}))
        info = self._adapter(http).describe()
        assert info.input_modalities == ("text", "image", "audio")

    def test_a_gateway_data_envelope_is_unwrapped(self):
        """Measured on OpenRouter: the model object arrives as {"data": {...}}. The
        spec object is flat and its "data" is only ever the list route's array, so
        unwrapping a dict cannot misread a spec answer."""
        http = self.SeqHttp((200, {"data": {"id": "m", "max_model_len": 40960,
                                            "architecture": {"modality": "text->text"}}}))
        info = self._adapter(http).describe()
        assert info.context_window == 40960
        assert info.input_modalities == ("text",)

    def test_meta_is_trimmed_to_what_consumers_act_on(self):
        """/api/show also ships tensors, the license and the whole modelfile --
        megabytes nobody plans with. Only the statements survive."""
        http = self.SeqHttp((200, self.MEAGRE), (200, self.SHOW))
        meta = self._adapter(http).describe().meta
        blob = str(meta)
        assert "tensors" not in blob and "modelfile" not in blob and "LLLL" not in blob
        assert meta["ollama_show"]["capabilities"] == ["completion", "tools", "thinking"]

    def test_capability_silence_stays_none_not_false(self):
        """Tri-state: a backend that says nothing about tools has not denied them --
        and one that says nothing about modalities has not declared text-only."""
        http = self.SeqHttp((200, {"id": "m", "context_window": 8192}))
        info = self._adapter(http).describe()
        assert info.supports_function_calling is None
        assert info.input_modalities is None
        assert info.output_modalities is None

    def test_nothing_answered_is_a_none_answer(self):
        """Measured: OpenAI's models route does not even resolve alias ids like
        gpt-5.6 -- 404. The follow-up /api/show probe 404s too. That is not an
        error; it is the answer 'no statement available'."""
        http = self.SeqHttp((404, {"error": {"message": "does not exist"}}), (404, {}))
        assert self._adapter(http).describe() is None

    def test_transport_failure_never_raises(self):
        class BoomHttp:
            def request(self, *a, **k):
                raise OSError("network down")
        assert CompletionLLMAdapter("m", _http=BoomHttp()).describe() is None

    class Catalog:
        """A ModelInfoProvider fake: fixed knowledge, records what was asked."""

        def __init__(self, info):
            self.info = info
            self.asked = []

        def describe(self, model):
            self.asked.append(model)
            return self.info

    def test_knowledge_fills_what_the_endpoint_left_unknown(self):
        """Measured motivation: OpenAI's endpoint states nothing usable -- with a
        catalogue injected, describe() still answers, and meta names the source."""
        catalog = self.Catalog(ModelInfo(context_window=272000, supports_reasoning=True,
                                         meta={"litellm": {"resolved_id": "gpt-5"}}))
        http = self.SeqHttp((200, self.MEAGRE), (404, {}))
        info = CompletionLLMAdapter("test-model", base_url="http://x/v1",
                                    model_info=catalog, _http=http).describe()
        assert info.context_window == 272000
        assert info.supports_reasoning is True
        assert catalog.asked == ["test-model"]
        assert "models_endpoint" in info.meta and "litellm" in info.meta

    def test_a_statement_outranks_knowledge(self):
        """The endpoint speaks for THIS deployment; a catalogue for the model family.
        Where both answer, the statement wins -- field by field, so knowledge still
        fills the gaps beside it."""
        catalog = self.Catalog(ModelInfo(context_window=999, max_output_tokens=64000,
                                         meta={"litellm": {}}))
        http = self.SeqHttp((200, {"id": "m", "max_model_len": 40960}))
        info = CompletionLLMAdapter("test-model", base_url="http://x/v1",
                                    model_info=catalog, _http=http).describe()
        assert info.context_window == 40960          # stated, not the catalogue's 999
        assert info.max_output_tokens == 64000       # unknown to the endpoint: filled

    def test_a_raising_provider_does_not_break_the_inquiry(self):
        class BoomCatalog:
            def describe(self, model):
                raise RuntimeError("catalogue exploded")

        http = self.SeqHttp((200, {"id": "m", "context_window": 8192}))
        info = CompletionLLMAdapter("test-model", base_url="http://x/v1",
                                    model_info=BoomCatalog(), _http=http).describe()
        assert info.context_window == 8192

    def test_knowledge_resolves_the_wire_spelling_for_openai_reasoning(self):
        """The derivation rule: reasoning + provider openai -> max_completion_tokens.
        Both facts come from the catalogue -- data application, not a URL heuristic."""
        catalog = self.Catalog(ModelInfo(supports_reasoning=True,
                                         meta={"models_dev": {"provider": "openai"}}))
        http = FakeHttp()
        CompletionLLMAdapter("gpt-5.6", model_info=catalog,
                             _http=http).complete("q", max_completion_tokens=100)
        assert http.last["json_body"]["max_completion_tokens"] == 100
        assert "max_tokens" not in http.last["json_body"]

    def test_the_rule_is_membership_not_the_arbitrary_pick(self):
        """Live failure this pins: 18 namespaces carry gpt-5.5 and the scan's entry
        came from 'abacus' -- but openai IS among the carriers, and that is the
        question the wire spelling depends on."""
        catalog = self.Catalog(ModelInfo(
            supports_reasoning=True,
            meta={"models_dev": {"provider": "abacus",
                                 "providers": ["abacus", "azure", "openai"]}}))
        http = FakeHttp()
        CompletionLLMAdapter("gpt-5.5", model_info=catalog,
                             _http=http).complete("q", max_completion_tokens=100)
        assert http.last["json_body"]["max_completion_tokens"] == 100

    def test_reasoning_elsewhere_keeps_the_default_spelling(self):
        """Measured: Ollama's and DeepSeek's reasoning models accept max_tokens fine.
        The rule needs BOTH facts, so reasoning alone changes nothing."""
        catalog = self.Catalog(ModelInfo(supports_reasoning=True,
                                         meta={"litellm": {"litellm_provider": "deepseek"}}))
        http = FakeHttp()
        CompletionLLMAdapter("deepseek-reasoner", model_info=catalog,
                             _http=http).complete("q", max_completion_tokens=100)
        assert http.last["json_body"]["max_tokens"] == 100

    def test_an_explicit_choice_wins_and_skips_the_lookup(self):
        catalog = self.Catalog(ModelInfo(supports_reasoning=True,
                                         meta={"models_dev": {"provider": "openai"}}))
        http = FakeHttp()
        CompletionLLMAdapter("gpt-5.6", model_info=catalog,
                             max_completion_tokens_field="max_tokens",
                             _http=http).complete("q", max_completion_tokens=100)
        assert http.last["json_body"]["max_tokens"] == 100
        assert catalog.asked == []

    def test_the_spelling_is_resolved_once_not_per_call(self):
        catalog = self.Catalog(ModelInfo(supports_reasoning=True,
                                         meta={"models_dev": {"provider": "openai"}}))
        http = FakeHttp()
        llm = CompletionLLMAdapter("gpt-5.6", model_info=catalog, _http=http)
        llm.complete("q", max_completion_tokens=100)
        llm.complete("q", max_completion_tokens=200)
        assert catalog.asked == ["gpt-5.6"]

    def test_no_budget_means_no_lookup(self):
        """Lazy on purpose: the spelling only matters once a budget is sent."""
        catalog = self.Catalog(ModelInfo(supports_reasoning=True,
                                         meta={"models_dev": {"provider": "openai"}}))
        http = FakeHttp()
        CompletionLLMAdapter("gpt-5.6", model_info=catalog, _http=http).complete("q")
        assert catalog.asked == []

    def test_a_stated_no_temperature_withholds_the_configured_default(self):
        """Measured: GPT-5 400s on any temperature but its default. When the
        catalogue STATES the rejection, a configured construction default is
        withheld instead of crashing the call."""
        catalog = self.Catalog(ModelInfo(supports_temperature=False))
        http = FakeHttp()
        CompletionLLMAdapter("gpt-5.6", temperature=0.2, model_info=catalog,
                             _http=http).complete("q")
        assert "temperature" not in http.last["json_body"]

    def test_silence_about_temperature_withholds_nothing(self):
        """Tri-state: None is not a rejection -- the configured value travels."""
        catalog = self.Catalog(ModelInfo(supports_reasoning=True))
        http = FakeHttp()
        CompletionLLMAdapter("m", temperature=0.2, model_info=catalog,
                             _http=http).complete("q")
        assert http.last["json_body"]["temperature"] == 0.2

    def test_a_per_call_temperature_wins_over_the_gate(self):
        """The call wins, always: a developer who names temperature on THIS call
        is stating backend knowledge, and the backend stays authoritative."""
        catalog = self.Catalog(ModelInfo(supports_temperature=False))
        http = FakeHttp()
        CompletionLLMAdapter("gpt-5.6", temperature=0.2, model_info=catalog,
                             _http=http).complete("q", temperature=1.0)
        assert http.last["json_body"]["temperature"] == 1.0

    def test_knowledge_is_fetched_once_for_field_and_gate_together(self):
        catalog = self.Catalog(ModelInfo(supports_reasoning=True,
                                         supports_temperature=False,
                                         meta={"models_dev": {"providers": ["openai"]}}))
        http = FakeHttp()
        llm = CompletionLLMAdapter("gpt-5.6", temperature=0.2, model_info=catalog,
                                   _http=http)
        llm.complete("q", max_completion_tokens=100)
        llm.complete("q", max_completion_tokens=100)
        assert catalog.asked == ["gpt-5.6"]
        assert "temperature" not in http.last["json_body"]
        assert http.last["json_body"]["max_completion_tokens"] == 100

    def test_a_raising_provider_falls_back_to_the_default_spelling(self):
        class BoomCatalog:
            def describe(self, model):
                raise RuntimeError("catalogue exploded")

        http = FakeHttp()
        CompletionLLMAdapter("m", model_info=BoomCatalog(),
                             _http=http).complete("q", max_completion_tokens=50)
        assert http.last["json_body"]["max_tokens"] == 50

    def test_knowledge_alone_is_still_an_answer(self):
        """Endpoint fully silent (404 twice), catalogue knows: the inquiry answers
        from knowledge rather than None -- meta keeps the provenance honest."""
        catalog = self.Catalog(ModelInfo(context_window=128000, meta={"models_dev": {}}))
        http = self.SeqHttp((404, {}), (404, {}))
        info = CompletionLLMAdapter("test-model", base_url="http://x/v1",
                                    model_info=catalog, _http=http).describe()
        assert info.context_window == 128000
        assert "models_dev" in info.meta and "models_endpoint" not in info.meta
