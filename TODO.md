# TODO

# Test and verify dynamic tool sets
Verfify if already possible to dynamically add tools to the tool set, by changing the configuration file or with that that the user can toggle tools on a GUI.

# Orchestrator for tool details calls
Injecting tools by the orchestrators strategy to list only titles, and the llm gets a tool to call the details.
Making larger toolsset more token efficient.

# Orchestrator with tool pagination
As tools grow in number, the orchestrator should be able to paginate the tools to avoid token limits.
For that the orchestartor should inject a pagination tool, when the tool set exceeds a certain number of tools.


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

## Observability: INFO-level logging at every layer transition

**Affects:** all packages — Adapters, ToolDrivers, Drivers, Orchestrators

**Status:** Open

**Priority:** High

**Problem:**
Open WebUI demonstrates what happens when observability is neglected: Tool
Server specs are fetched with success logged at `DEBUG` only, failures are
silently swallowed with `continue`, and the UI gives zero feedback on whether
tools were loaded.  The result is an undebuggable black box — users cannot
tell if a tool server connected, how many tools were registered, or why
nothing works.

MCS must avoid this pattern.  Every layer transition (Adapter connect,
ToolDriver registration, Driver init, Orchestrator tool injection) should
produce at least one `INFO`-level log entry on success **and** a clear
`WARNING`/`ERROR` on failure — including actionable context (URL, tool count,
error reason).

**Concrete requirements:**

1. **Adapter** — log on connect/disconnect with target info (URL, path, host).
2. **ToolDriver** — log number of tools registered after adapter init
   (`INFO: ToolDriver registered 12 tools from <source>`).
3. **Driver** — log which tools were injected into the prompt and whether
   native or text-based tool calling is used.
4. **Orchestrator** — log strategy selection, pagination state, and final
   tool count delivered to the driver.
5. **Errors** — never silently `continue` past a failed connection or parse
   error. Always log with enough context to diagnose without a debugger.

**Anti-patterns to avoid (learned from Open WebUI):**
- Success on `DEBUG`, failure on `ERROR` but swallowed → user sees nothing.
- No UI/API feedback on tool registration status.
- Lazy loading without any signal that loading happened.

---

## Deprecate / yank `mcs-drivers-core` on PyPI

**Affects:** PyPI

**Status:** Open

**Problem:**
An earlier version was published under the name `mcs-drivers-core` (plural).
The canonical name is now `mcs-driver-core` (singular, consistent with the
`mcs-driver-<capability>` naming convention). The old package should be
yanked or updated with a deprecation notice pointing to `mcs-driver-core`.
