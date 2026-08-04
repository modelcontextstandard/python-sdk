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

    def _kwargs(self, messages: list[dict], stream: bool) -> dict:
        kwargs: dict[str, Any] = {"model": self.model, "messages": messages}
        if stream:
            kwargs["stream"] = True
        if self.api_base:
            kwargs["api_base"] = self.api_base
            kwargs["api_key"] = self.api_key or "no-key"
        if self.tools:
            kwargs["tools"] = self.tools
        return kwargs

    def complete(self, messages: list[dict]) -> dict:
        """One turn, assembled. Returns the raw ``choices[0].message`` dict."""
        resp = completion(**self._kwargs(messages, stream=False))
        assert isinstance(resp, ModelResponse)
        choice = resp.choices[0]
        assert isinstance(choice, Choices)
        return choice.message.model_dump()

    def stream(self, messages: list[dict]) -> Iterator[Any]:
        """One turn, chunk by chunk. The chunks go straight into the buffer."""
        return completion(**self._kwargs(messages, stream=True))  # type: ignore[return-value]
