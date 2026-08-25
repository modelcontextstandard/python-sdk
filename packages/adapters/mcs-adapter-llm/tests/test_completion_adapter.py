"""Chat Completions adapter: request shape, response reading, error translation.

Every test runs offline against an injected fake transport (``_http``) -- which is what
the DPI slot is for. Nothing here needs a key, a network or a model.
"""

from __future__ import annotations

import json

import pytest

from mcs.adapter.llm.completion import CompletionLLMAdapter
from mcs.types.http import HttpResponse
from mcs.types.llm import ContextWindowExceeded, LLMError, LLMPort


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
        assert (usage.prompt, usage.completion, usage.total) == (52, 8, 60)

    def test_unreported_usage_is_none_not_zero(self):
        """"Not reported" and "none spent" are different facts, and a caller calibrating
        an estimate must skip the first rather than record it as costing nothing."""
        usage = _adapter(FakeHttp(payload=_answer("ok"))).complete("q").usage
        assert usage.prompt is None and usage.total is None

    def test_reasoning_and_cached_breakdowns_are_read(self):
        payload = _answer("ok", usage={
            "prompt_tokens": 100, "completion_tokens": 319, "total_tokens": 419,
            "completion_tokens_details": {"reasoning_tokens": 300},
            "prompt_tokens_details": {"cached_tokens": 64},
        })
        usage = _adapter(FakeHttp(payload=payload)).complete("q").usage
        assert usage.reasoning == 300 and usage.cached == 64

    def test_ollama_field_names_are_understood(self):
        payload = _answer("ok", usage={"prompt_eval_count": 52, "eval_count": 8})
        usage = _adapter(FakeHttp(payload=payload)).complete("q").usage
        assert (usage.prompt, usage.completion, usage.total) == (52, 8, None)

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
