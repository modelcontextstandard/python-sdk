"""The LLM port for MCS -- the little a component needs to ask a model one question.

MCS does not own the LLM loop. The *client* does, and that is deliberate: it holds the
conversation, the history, the streaming, the tool rounds. Nothing in this package
changes that.

But some MCS components need a model for a **bounded sub-task** of their own -- a
summarizer condensing a document it was handed, for instance. Those need a way to ask
*one* question and get *one* answer, without pulling a provider SDK into a driver.

**One method, and that is the design.** No streaming, no tools, no multimodality, no
conversation state -- all of that belongs to the client's loop. Nor any model *metadata*:
a context window and a tokenizer describe the model, not the connection to it, and an
implementation that had to answer for them would be guessing on behalf of whoever chose
the model. What comes back instead is what the backend actually measured (see
:class:`~mcs.types.llm.LLMResponse`), which is exact where a guess would not be.

Because the surface is this small, adapting an LLM a client *already has* is a three-line
adapter, which is the point:

    class MyLLM:                       # the client's own, with its cost tracking,
        model = "my-house-model"       # or None -- see LLMPort.model
        def complete(self, prompt, *, system=None, max_completion_tokens=None, **kwargs):
            return LLMResponse(text=my_existing_stack.ask(prompt, system))

A client that has built token accounting, cost tracking or PII filtering into its LLM
path should lend *that* -- not have MCS open a second, ungoverned route to a provider.
Shipping an adapter is a convenience for clients that have no such stack; it must never
be what happens silently when a client passes nothing.

This module has **zero** runtime dependencies.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from .response import LLMResponse


@runtime_checkable
class LLMPort(Protocol):
    """Minimal contract for calling a language model once.

    Implementations may wrap a provider SDK, an OpenAI-compatible HTTP endpoint, a local
    server, or a client's existing in-house stack. What they must not do is surprise the
    caller: one call in, one answer out.
    """

    @property
    def model(self) -> str | None:
        """The model id currently behind this port, or ``None`` when unknown.

        Part of the port -- not a separate capability -- for one reason above all:
        the model id must live in exactly ONE place. The implementation was
        constructed with it; repeating it anywhere else (a consumer's constructor, a
        config file) is duplicated configuration, and duplicated configuration
        drifts -- an adapter speaking qwen while a summarizer was told gpt would pick
        wrong prompt variants with no error anywhere. So consumers ask the port, per
        run.

        Per-run asking also means per-model behaviour follows the model at call time:
        an agent may switch models mid-operation (a router port, a fallback chain),
        and a router answers with the *currently active* id. That is a corollary, not
        the justification -- with a fixed adapter, resolution is a cached lookup and
        the consumer behaves exactly like a fixed, configure-once object.

        This is deliberately different from the metadata kept OUT of the port
        (context window, tokenizer): those an implementation cannot know and would
        have to guess. Its model id is a construction fact -- and ``None`` stays
        honest where even that is unknown (an anonymous gateway, a wrapper that does
        not care). Consumers treat ``None`` as "base behaviour, no variants".

        A read-only *property* rather than an attribute, and not only because
        consumers never write it: a mutable protocol attribute is invariant, so an
        implementation whose ``model`` is a plain ``str`` would fail to typecheck
        against ``str | None``. Property access is covariant -- a simple attribute
        (``self.model = "qwen3:4b"``, ``model = None``) and a computed property (a
        router) both satisfy it.
        """
        ...

    def complete(
        self,
        prompt: str,
        *,
        system: str | None = None,
        max_completion_tokens: int | None = None,
        **kwargs: Any,
    ) -> LLMResponse:
        """Answer *prompt* and return the model's response.

        Parameters
        ----------
        prompt :
            The user-side instruction, already assembled by the caller.
        system :
            Optional system instruction. Separate from *prompt* because steering
            ("answer only from the text below") and payload (the text) come from
            different places and deserve different weight; an implementation whose
            backend has no system role may prepend it.
        max_completion_tokens :
            Upper bound on the answer -- named after what it actually caps: the
            completion, *including* any reasoning the model spends inside it (an eaten
            budget surfaces as ``LLMResponse.truncated``). ``None`` leaves it to the
            implementation. Named -- not left to *kwargs* -- because it is the one thing
            a caller must be able to say *without* knowing the backend: the wire spells
            it ``max_tokens`` on older and local servers and ``max_completion_tokens``
            on OpenAI's reasoning models, and only the implementation knows which. This
            is deliberately the single translation the port asks of an implementation.
        **kwargs :
            Everything else, passed to the backend **verbatim**; the call wins over the
            construction. This is what keeps the port fit for every LLM interaction
            inside MCS without growing named parameters: stop sequences, a JSON
            ``response_format``, a backend-specific knob. Nothing is validated -- the
            backend is authoritative, and the developer who wired a backend in knows
            what it takes.

        The named trio is the **portable core**, and the split follows who can answer
        for a parameter. ``prompt``/``system``/``max_completion_tokens`` are the caller's task
        knowledge, meaningful behind any backend -- a reusable component (a summarizer)
        should need nothing else. Sampling defaults (temperature and friends) are
        knowledge about the *model*: whether 0.2 helps or is refused depends on what
        somebody else chose (GPT-5 rejects every value but its default -- measured), so
        their defaults belong to the implementation's construction, and per-call
        ``kwargs`` are a statement about the specific backend this caller knows it was
        given -- a component that leans on them narrows which models it runs on.

        Raises
        ------
        ContextWindowExceeded
            When the request did not fit the model's window. Its own type because it is
            the one failure a caller can act on -- send less and try again. Since nothing
            here reports a window up front, this is often where the real limit is first
            stated; see :mod:`mcs.types.llm.errors`.
        LLMError
            Anything else the backend refused or could not answer.
        """
        ...
