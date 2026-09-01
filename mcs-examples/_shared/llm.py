"""The LLM transport -- the only place these examples talk to a provider.

Deliberately thin: build the request, hand back either the assembled message
(non-streaming) or the raw chunk iterator (streaming). It never inspects the
content, because interpreting an LLM response is the driver's job -- that is the
whole promise of MCS.
"""

from __future__ import annotations

from typing import Any, Iterator

from litellm import completion, ModelResponse
from litellm.types.utils import Choices


class LLM:
    """One configured model endpoint."""

    def __init__(self, model: str, api_base: str | None = None,
                 api_key: str | None = None, tools: list[dict] | None = None) -> None:
        self.model = model
        self.api_base = api_base
        self.api_key = api_key
        self.tools = tools
        #: Cumulative measured usage of THIS conversation's model, session-wide,
        #: in the neutral vocabulary (input/output/reasoning/cache_read). The tool
        #: layer's models report their own numbers through tool results -- adding
        #: them here would double-count.
        self.spent: dict[str, int] = {}

    def _kwargs(self, messages: list[dict], stream: bool) -> dict:
        kwargs: dict[str, Any] = {"model": self.model, "messages": messages}
        if stream:
            kwargs["stream"] = True
            # Without this the usage block never arrives on a stream -- providers
            # send it on the final chunk only when asked (Ollama's /v1 included).
            kwargs["stream_options"] = {"include_usage": True}
        if self.api_base:
            kwargs["api_base"] = self.api_base
            kwargs["api_key"] = self.api_key or "no-key"
        if self.tools:
            kwargs["tools"] = self.tools
        return kwargs

    def _note_usage(self, usage: Any) -> None:
        """Accumulate one provider usage block.

        litellm normalises to the Chat Completions spelling (prompt/completion);
        the counters keep the neutral one (input/output) -- one translation, here.
        """
        if usage is None:
            return

        def read(obj: Any, key: str) -> Any:
            return obj.get(key) if isinstance(obj, dict) else getattr(obj, key, None)

        for name, value in (
            ("input", read(usage, "prompt_tokens")),
            ("output", read(usage, "completion_tokens")),
            ("reasoning", read(read(usage, "completion_tokens_details"),
                               "reasoning_tokens")),
            ("cache_read", read(read(usage, "prompt_tokens_details"),
                                "cached_tokens")),
        ):
            if isinstance(value, int) and value:
                self.spent[name] = self.spent.get(name, 0) + value

    def complete(self, messages: list[dict]) -> dict:
        """One turn, assembled. Returns the raw ``choices[0].message`` dict."""
        resp = completion(**self._kwargs(messages, stream=False))
        assert isinstance(resp, ModelResponse)
        self._note_usage(getattr(resp, "usage", None))
        choice = resp.choices[0]
        assert isinstance(choice, Choices)
        return choice.message.model_dump()

    def stream(self, messages: list[dict]) -> Iterator[Any]:
        """One turn, chunk by chunk. The chunks go straight into the buffer --
        usage is skimmed off in passing (it rides the final chunk, see _kwargs)."""
        for chunk in completion(**self._kwargs(messages, stream=True)):  # type: ignore[union-attr]
            self._note_usage(getattr(chunk, "usage", None))
            yield chunk
