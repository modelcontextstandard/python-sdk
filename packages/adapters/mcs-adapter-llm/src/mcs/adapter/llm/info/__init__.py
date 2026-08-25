""":class:`~mcs.types.llm.ModelInfoProvider` implementations over maintained catalogues.

The **knowledge** half of model information. The *statement* half lives on each LLM
adapter's ``describe()`` -- asking its own endpoint what it states. But some backends
state nothing useful (measured: OpenAI's ``/v1/models/{id}`` answers bookkeeping only),
and there the community-maintained catalogues fill in. Knowledge may lag reality or
describe a different deployment -- a catalogue cannot know a local server's ``num_ctx``
-- which is why consumers merge *statement before knowledge*::

    llm = CompletionLLMAdapter("gpt-5.6", api_key=..., model_info=ModelsDevInfoProvider())
    llm.describe()                          # endpoint first, catalogue fills the gaps

    ModelsDevInfoProvider().describe("gpt-5.6")     # or standalone, no adapter needed

One module per source: :mod:`.catalog` holds the shared mechanics (public base --
subclass it for a house database), :mod:`.litellm` and :mod:`.models_dev` wrap the two
public catalogues.
"""

from .catalog import ModelInfoCatalog
from .litellm import DEFAULT_LITELLM_URL, LiteLLMInfoProvider
from .models_dev import DEFAULT_MODELS_DEV_URL, ModelsDevInfoProvider

__all__ = [
    "ModelInfoCatalog",
    "LiteLLMInfoProvider",
    "ModelsDevInfoProvider",
    "DEFAULT_LITELLM_URL",
    "DEFAULT_MODELS_DEV_URL",
]
