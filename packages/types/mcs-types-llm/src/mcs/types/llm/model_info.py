"""What a backend *states* about its model -- transported, never guessed.

The port's rule stands: an implementation must not answer for model metadata it cannot
know -- a guessed context window plans confidently and overflows. But most backends can
be **asked**: nearly every server has a model-info route, and relaying a backend's own
statement is transport, the same category as ``usage``. ``ModelInfo`` is that
statement, normalised to the few fields consumers act on; everything else rides in
``meta``.

Measured reality that shaped these fields (against live endpoints):

- OpenAI ``/v1/models/{id}``: four bookkeeping fields, nothing usable -- and alias ids
  (``gpt-5.6``) are not even resolved there, only by the completions endpoint.
- Ollama's OpenAI-compatible ``/v1/models/{id}``: equally meagre. Its native
  ``/api/show`` is rich: ``capabilities: ['completion', 'tools', 'thinking']`` plus the
  architecture's context length.
- The catch: Ollama *states* the model card's limit (262 144 for a qwen3:4b) while
  *serving* a smaller ``num_ctx`` (32 768 on the same box, measured via silent
  clipping). A statement is not a guarantee -- plan with what is stated, and keep the
  nets (overflow learning, the summarizer's clip detector) in force.
- Modalities are stated too, in two dialects. Ollama's ``capabilities`` names what a
  model understands (``vision``, ``audio`` -- measured on a gemma4:e4b) without naming
  a direction; OpenRouter-style gateways state both directions explicitly
  (``architecture.input_modalities: ['text', 'image', ...]`` and
  ``output_modalities``, with the older ``modality: "text+image->text"`` string as
  fallback -- 26 distinct profiles measured across one gateway's catalogue).

This module has **zero** runtime dependencies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


@dataclass(frozen=True)
class ModelInfo:
    """One backend's statement about one model. Every field may be unknown.

    Attributes
    ----------
    context_window :
        Total token window **as stated by the backend**. May exceed what the instance
        actually serves (see the Ollama catch in the module docstring) -- consumers
        plan with it and rely on their nets, exactly as with any other configuration.
    max_output_tokens :
        Stated ceiling for a single completion, where the backend names one.
    supports_function_calling :
        Whether the model takes native tool schemas. **Tri-state on purpose**:
        ``None`` means "not stated", which is a different fact from ``False`` ("stated
        as unsupported") -- collapsing the two would turn silence into a denial.
    supports_reasoning :
        Whether the model thinks before answering (and hence eats answer budget doing
        so). Tri-state for the same reason.
    supports_temperature :
        Whether the model accepts a ``temperature`` at all. **Stated as False** by
        models.dev for OpenAI's reasoning models -- and measured: GPT-5 rejects every
        value but its default with a 400. LiteLLM's JSON says nothing here, so it
        stays ``None`` there. The point of carrying it: a consumer can *withhold* a
        configured temperature when the model is stated to reject one -- silence
        (``None``) withholds nothing.
    input_modalities :
        What the model **accepts**, as stated -- lowercase names in the backends' shared
        vocabulary (``text``, ``image``, ``audio``, ``video``, ``file``), order as
        stated, never validated here. ``None`` means the backend said nothing, which is
        different from ``("text",)`` ("stated as text-only"). The input side is the one
        that matters most in practice: whether an image can be *sent* decides a
        caller's request shape, while output beyond text is still the exception.
    output_modalities :
        What the model **produces**, as stated. Same vocabulary, same tri-state logic;
        image-producing chat models exist and gateways do state them.
    meta :
        The trimmed raw statements this info was read from, keyed by source (e.g.
        ``models_endpoint``, ``ollama_show``) -- so a consumer can see *what the
        backend actually said* when a normalised field surprises.
    """

    context_window: int | None = None
    max_output_tokens: int | None = None
    supports_function_calling: bool | None = None
    supports_reasoning: bool | None = None
    supports_temperature: bool | None = None
    input_modalities: tuple[str, ...] | None = None
    output_modalities: tuple[str, ...] | None = None
    meta: dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class ModelInfoProvider(Protocol):
    """A source of :class:`ModelInfo` for models it does not serve -- knowledge, not
    statement.

    The counterpart to :meth:`~mcs.types.llm.LLMPort.describe`, split by who can
    answer: a *port* describes the one model behind its own connection (no argument --
    it knows which), a *provider* is asked about **any** model by id (a catalogue: a
    maintained database, a snapshot, a service). Same vocabulary, same ``None``
    semantics -- no entry, no source, or a failed lookup are all the ``None``-shaped
    answer, never an exception.

    The distinction matters to consumers: what a port relays its backend *stated* is
    ground truth for that connection; what a provider knows is maintained data that may
    lag reality or describe a different deployment (a catalogue cannot know a local
    server's ``num_ctx``). Statement beats knowledge -- merge in that order.

    Implementations that reach over the network take the client's transport injected,
    like every MCS component: a provider is a data source, never a second, ungoverned
    route.
    """

    def describe(self, model: str) -> ModelInfo | None:
        """What this source knows about *model*, or ``None``."""
        ...
