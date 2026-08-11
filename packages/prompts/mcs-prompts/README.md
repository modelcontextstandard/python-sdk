# mcs-prompts

**Prompt loading for the Model Context Standard (MCS)** — the mechanism, never the
prompts.

```python
from mcs.prompts import load_prompts

bundle = load_prompts(
    "mcs.types.summarizer",          # whose shipped defaults
    override="./my_prompts.toml",    # optional: the developer's own
)
prompts = bundle.resolve(model="qwen3:4b")   # per RUN -- the model can change
prompts["stuff"]                             # -> template string
```

## The rule this package enforces by existing

**No MCS component hardcodes a prompt.** Every word a component says to a model is
data — tunable per model, replaceable by the developer. Per-model prompt engineering is
real work (Cursor maintains distinct prompts per model family; the phrasing a 4B local
model needs is noise to a frontier model), and it must never require forking Python
code.

This package therefore contains **no prompts**. The prompts live with their owners:
each package ships its defaults as package data (`prompts/default.toml` next to its
code) — the same way the core ships its tool-call codec TOML. What lives here, once, is
the loading every owner would otherwise reimplement.

## The TOML convention

**The file belongs to the component; `[prompts]` is this loader's reserved namespace
inside it.** A component may keep its own configuration in the same file (the core's
codec TOML carries `[meta]`, `[parsing]` and `[[healing]]` regex rules) — the loader
reads `[prompts]` and ignores the rest.

Inside `[prompts]`: **flat `name = "string"`.** A prompt is a string — one key, one
text. Placeholder documentation (`{query}`, `{text}`) is the component's API contract
and lives as a TOML comment next to the template, not as structure:

```toml
[prompts]
# placeholders: {query} {text}
stuff = "Question: {query} ..."          # base templates

[prompts."model:qwen*"]                  # variant: fnmatch pattern on the model id
stuff = "... preserve the order ..."
```

Variants are **model-centric blocks**, not per-prompt nesting: whoever tunes qwen
thinks "what does qwen need?" and edits one block covering every affected prompt —
per-prompt variant tables would scatter one model's tuning across the file and demand a
second resolution rule.

Precedence, weakest to strongest:

    package base -> package model variants -> override base -> override model variants

Overrides are **sparse**: only the names present replace the defaults. Within one file,
later matching variant sections win — write the more specific pattern further down.

Should per-prompt *metadata* ever earn its keep (declared placeholders for validation,
say), the compatible extension is a `[prompts.<name>]` table with a `template` field —
distinguishable from variants by the missing `model:` prefix. Until a consumer exists,
the loader rejects such tables loudly rather than half-supporting them.

## Load once, resolve per run

The Java `ResourceBundle` idea, with the model id in the locale's role. Loading and
resolving are separate **because the model moves**: an agent switches tiers, a router
port falls back — so a consumer keeps its bundle and resolves each run with whatever
its `LLMPort` currently names (`llm.model`). Nobody passes a model id into a component;
it asks the one party that knows, at the moment it matters. Resolution is cached per
id, so the common case costs a dictionary lookup.

## Failure is loud and didactic

A missing prompt name lists what exists; a missing defaults file names the convention;
junk in a `[prompts]` table is an error at load, not a template that silently never
applies.

## Cross-concern placement

This sits beside `auth`, `hooks` and `permission` — MCS's pattern for concerns that cut
across components: the core carries at most the contract, never the mechanism. Zero
third-party dependencies (`tomllib` is stdlib, hence Python ≥ 3.11).

## Installation

```bash
pip install mcs-prompts
```

## Links

- **Homepage:** <https://www.modelcontextstandard.io>
- **Source:** <https://github.com/modelcontextstandard/python-sdk>

## License

Apache-2.0
