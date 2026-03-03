# TODO

## Extract model-capability lookup from litellm dependency

**Affects:** `packages/core/src/mcs/driver/core/base.py` → `_model_supports_native_tools()`

**Status:** Open / Undecided

**Problem:**
`DriverBase._model_supports_native_tools()` uses a lazy import of
`litellm.supports_function_calling()` to check whether a model supports native
tool calls. This implicitly pulls in the entire `litellm` dependency (including
~2600 model entries in `model_cost`) into `mcs-core`.

**Options:**

1. **Standalone package `mcs-model-registry`** – references / caches the
   `litellm.model_cost` JSON and exposes a slim
   `supports_function_calling(model)` API without the rest of litellm.
2. **Explicit configuration** – the capability is supplied from outside
   (e.g. via `DriverMeta`, a constructor parameter, or a pluggable registry).
3. **Keep the status quo** – lazy import with no hard dependency entry;
   works without litellm (fallback `False`).

**Trade-offs:**
- The driver should ideally not need to actively fetch anything at runtime.
- litellm itself may fetch `model_cost` from the network – requires
  connectivity.
- Prompts are already designed to be loadable at runtime → a similar pattern
  could apply here.
- Not a blocking issue since the fallback (`False`) works reliably.

---

## Extraction chain edge case: native-tool model called without `tools`

**Affects:** `packages/core/src/mcs/driver/core/base.py` → `_extract()`

**Status:** Open

**Problem:**
The claim-based extraction chain distinguishes native tool-call responses from
plain text by inspecting the **response shape** (e.g. presence of a
`"tool_calls"` key). This covers >99% of practical cases, but an edge case
remains: when a native-tool-capable model is called **without** `tools` and
produces JSON in `content` that resembles a text-based tool call,
`TextExtractionStrategy` could false-positive.

**Possible solutions:**
1. Pass `model_name` to `process_llm_response` so the extraction chain can
   be context-aware (implies a signature change).
2. Introduce session-level state after `get_driver_context` – the driver
   remembers whether native tools were supplied and skips text extraction
   accordingly.
3. Accept the edge case as negligible for now (models called with `tools`
   will always use native format; without `tools` the text strategy is the
   only sensible fallback anyway).
4. Setting the model name in the driver fix, or the format to choose. Maybe with 
   the Strategy, since GPT-4.o and GPT-5 following the same pattern.

---

## CI/CD pipeline for automated PyPI publishing

**Affects:** `.github/workflows/`

**Status:** Open / Planned

**Problem:**
Publishing to PyPI is currently a manual process (`build` + `twine upload`
for each package). With 9 independently versioned packages this is
error-prone and tedious.

**Desired state:**
A GitHub Actions workflow that:

1. Triggers on version-tag push (e.g. `mcs-driver-core/v0.3.0`).
2. Builds the tagged package (`python -m build`).
3. Runs the test suite for that package.
4. Publishes to PyPI via `twine` using a trusted publisher (OIDC) or
   API token stored in GitHub secrets.

**Considerations:**
- Each package has its own release cadence → per-package tags are preferable
  over a single monorepo tag.
- A matrix build for all packages on every push to `main` (lint + test only,
  no publish) would catch regressions early.
- `uv` could be used in CI for faster dependency resolution.

---

## Deprecate / yank `mcs-drivers-core` on PyPI

**Affects:** PyPI

**Status:** Open

**Problem:**
An earlier version was published under the name `mcs-drivers-core` (plural).
The canonical name is now `mcs-driver-core` (singular, consistent with the
`mcs-driver-<capability>` naming convention). The old package should be
yanked or updated with a deprecation notice pointing to `mcs-driver-core`.
