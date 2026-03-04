# Contributing to MCS Python SDK

Thanks for your interest in MCS. We're building an open ecosystem --
your ideas power it.

## Step 0 -- Read the spec

Seriously. Before writing code, read the
[MCS Specification](https://modelcontextstandard.io). It's short ;-), it
explains the *why* behind every design decision, and it'll save you
from building something that already exists or conflicts with the
architecture. Everything in this SDK follows that spec.

## Getting started

```bash
git clone https://github.com/modelcontextstandard/python-sdk.git
cd python-sdk
pip install uv
uv sync --extra examples
uv run python -m pytest packages/core/tests/ -q
```

The repo is a `uv` workspace. All packages live under `packages/`:

```
packages/
  core/                         # mcs-core (interfaces, DriverBase, PromptStrategy)
  adapters/
    mcs-adapter-http/           # HTTP transport
    mcs-adapter-localfs/        # Local filesystem
    mcs-adapter-smb/            # SMB/CIFS shares
  drivers/
    mcs-driver-rest/            # OpenAPI → LLM tools
    mcs-driver-filesystem/      # File operations
    mcs-driver-csv/             # CSV queries
  orchestrators/
    mcs-orchestrator-base/      # Multi-driver aggregation
    mcs-orchestrator-rest/      # REST-specific orchestrator
```

## Where to contribute

### New drivers (highest impact)

The SDK needs more drivers. Pick a protocol or capability and build it:

- **GraphQL**, **MQTT**, **gRPC**, **WebSocket**
- Domain-specific: **PDF**, **database**, **calendar**, **CAN-Bus**
- Or anything you wish an LLM could talk to

Follow the bottom-up workflow from the README:
**Port → Adapter → ToolDriver → Driver**.

Each ToolDriver has exactly one responsibility. If your capability
spans multiple protocols (like mail = IMAP + SMTP), publish the
ToolDrivers as `-toolonly` packages and compose them in a higher-level
driver.

### New adapters

An adapter handles I/O for a specific backend. If a driver already
exists (e.g. `mcs-driver-filesystem`) but needs a new backend
(e.g. S3, GCS, Azure Blob), write an adapter that satisfies the
driver's Port protocol. No changes to the driver needed.

### Core improvements

- **PromptStrategy**: New formats (XML, YAML), model-specific tuning
- **ExtractionStrategy**: Better parsing for new LLM output formats
- **DriverBase**: Performance, error messages, edge cases
- **Tests**: The `packages/core/tests/` suite needs more coverage

### Documentation & examples

- Real-world integration examples in `mcs-examples/`
- Tutorials for building custom drivers
- Improvements to the specification docs

## Conventions

### Package structure

Before writing code, set up the directory layout. The convention
ensures that every MCS package resolves to the same `mcs.*` namespace
-- both on PyPI and in the IDE. Autocomplete, jump-to-definition, and
`from mcs.driver.mail import MailDriver` all work because of this
structure.

**Driver package** (`mcs-driver-mail`):

```
packages/drivers/mcs-driver-mail/
  pyproject.toml
  src/
    mcs/
      driver/
        mail/
          __init__.py       # exports MailDriver
          driver.py         # MailDriver(DriverBase)
          tooldriver.py     # MailToolDriver(MCSToolDriver)  -- optional if HybridDriver
          ports.py          # Protocol definitions
```

**Adapter package** (`mcs-adapter-imap`):

```
packages/adapters/mcs-adapter-imap/
  pyproject.toml
  src/
    mcs/
      adapter/
        imap/
          __init__.py       # exports ImapAdapter
          adapter.py        # ImapAdapter
```

The `src/mcs/` path is critical -- it's what makes the `mcs` namespace
package work across all installed packages. Skip it, and imports break.
Orchestrators follow the same pattern: `src/mcs/orchestrator/<name>/`.

### Naming

| Level | Pattern | Example |
| --- | --- | --- |
| PyPI (Driver) | `mcs-driver-<capability>` | `mcs-driver-mail` |
| PyPI (Adapter) | `mcs-adapter-<protocol>` | `mcs-adapter-imap` |
| PyPI (Orchestrator) | `mcs-orchestrator-<name>` | `mcs-orchestrator-base` |
| Python import | `mcs.driver.<capability>` | `from mcs.driver.mail import MailDriver` |
| src layout | `src/mcs/{driver,adapter,orchestrator}/<name>/` | `src/mcs/driver/mail/` |
| Class | `<Capability>Driver` | `MailDriver` |

### Code style

- Python >= 3.9, type hints everywhere
- Docstrings for public APIs (NumPy style)
- No hardcoded LLM text in Python -- prompt text belongs in TOML files
  or in `Tool.description` fields
- Adapters never import from drivers (structural subtyping via Protocol)

### Commit messages

Look at `git log` for the style. Keep them concise, focused on the
"why". One logical change per commit.

## Submitting a PR

1. Fork the repo and create a branch from `main`
2. Make your changes
3. Run tests: `uv run python -m pytest packages/core/tests/ -q`
4. Build check: `python scripts/build_all.py --build --check`
5. Open a PR with a clear description of what and why

## License

By contributing, you agree that your contributions will be licensed
under Apache-2.0, consistent with the project license.

---

Questions? Open a [GitHub Discussion](https://github.com/modelcontextstandard/python-sdk/discussions)
or file an issue. PRs welcome.
