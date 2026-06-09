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

## CredentialProvider -- universelle Auth-Abstraktion für Adapter

**Affects:** alle Adapter-Pakete, neuer `mcs-credential-core` oder Teil von `mcs-driver-core`

**Status:** Open / Design Phase

**Problem:**
Jeder Adapter löst Authentifizierung aktuell selbst: IMAP/SMTP nehmen
`user + password`, HTTP nimmt `headers`, LocalFS braucht nichts. Mit
OAuth2-basierten Backends (Gmail API, Microsoft Graph, Slack, GitHub, ...)
kommt ein ganz anderer Auth-Flow hinzu: Token Vault, OAuth2 Refresh,
Service Accounts, etc.

Ohne gemeinsame Abstraktion müsste jeder Adapter seinen eigenen
OAuth-Code mitbringen -- oder fest an einen Anbieter (Auth0, Azure AD)
gebunden sein.

**Gewünschter Zustand:**
Ein `CredentialProvider`-Protocol (structural typing, wie `MailboxPort`),
das Adaptern eine einheitliche Schnittstelle für Credentials bietet:

```python
@runtime_checkable
class CredentialProvider(Protocol):
    def get_access_token(self) -> str: ...
```

Konkrete Implementierungen:
- `StaticCredentials(user, password)` -- für IMAP, SMTP, SMB
- `Auth0TokenVaultProvider(domain, client_id, ...)` -- OAuth2 via Auth0
- `OAuthRefreshProvider(client_id, secret, refresh_token)` -- direkter OAuth2
- `EnvCredentials(env_var)` -- aus Umgebungsvariablen

Adapter akzeptieren dann optional `credentials: CredentialProvider` als
Alternative zu expliziten `user + password` Parametern.

**Offene Fragen:**
- Gehört das in `mcs-driver-core` oder ein eigenes `mcs-credential-core`?
- Brauchen wir neben `get_access_token()` auch `get_username()`,
  `get_headers()`, etc.?
- Wie geht man mit Token-Refresh (Expiry, Retry) um?
- Soll der Provider synchron oder async sein?
- Zusammenspiel mit Auth0 Token Vault: Token Exchange vs. Direct Token.

**Kontext:**
Auth0 Hackathon "Authorized to Act" (Deadline: 2026-04-06) ist ein guter
Anlass, das Pattern in einem Beispielprojekt (`mcs-examples/gmail_agent`)
zu validieren, bevor es in die Core-Library wandert.

---

## Lazy adapter/connector initialization for tool discovery

**Affects:** all ToolDrivers and Adapters/Connectors (especially `mcs-driver-mailread`, `mcs-driver-mailsend`)

**Status:** Open

**Priority:** Medium

**Problem:**
Adapters and connectors validate credentials eagerly in `__init__`, even though
`list_tools()` returns static metadata that never touches the adapter.  This
means callers must provide valid credentials just to discover available tools.

**Example chain (Gmail):**
```
MailDriver.__init__
  → MailToolDriver.__init__
    → MailreadToolDriver.__init__
      → GmailMailboxConnector.__init__
        → raise ValueError("Either 'access_token' or '_credential' must be provided")
```

But `MailreadToolDriver.list_tools()` is just `return list(_TOOLS)` -- a static
constant that does not need the adapter at all.

**Impact:**
- The Skill Generator (`scripts/skill_generator.py`) must inject a dummy
  credential to instantiate auth-aware drivers for tool discovery.
- Any tooling that wants to introspect tools (inspectors, registries, UIs)
  hits the same problem.
- Violates Interface Segregation: `list_tools()` and `execute_tool()` have
  completely different resource requirements, but `__init__` validates for
  the latter.

**Fix:**
Store credential parameters in `__init__` without validation.  Validate on
first actual use (`_get_token()`, `connect()`, or first `execute_tool()` call).

```python
# Before (eager -- blocks tool discovery)
def __init__(self, *, access_token=None, _credential=None):
    if _credential is not None:
        self._token = lambda: _credential.get_token("gmail")
    elif access_token is not None:
        self._token = access_token
    else:
        raise ValueError(...)

# After (lazy -- list_tools() works without credentials)
def __init__(self, *, access_token=None, _credential=None):
    self._credential = _credential
    self._access_token = access_token

def _get_token(self) -> str:
    if self._credential is not None:
        return self._credential.get_token("gmail")
    if self._access_token is not None:
        return self._access_token if isinstance(self._access_token, str) else self._access_token()
    raise ValueError("Either 'access_token' or '_credential' must be provided")
```

**Affected files (non-exhaustive):**
- `packages/drivers/mcs-driver-mailread/src/mcs/driver/mailread/gmail_connector.py`
- `packages/drivers/mcs-driver-mailsend/src/mcs/driver/mailsend/gmail_sender.py`
- `packages/adapters/mcs-adapter-imap/src/mcs/adapter/imap/adapter.py`
- `packages/adapters/mcs-adapter-smtp/src/mcs/adapter/smtp/adapter.py`
- Any future adapter that validates credentials in `__init__`

**Related:** `.cursor/rules/lazy-adapter-init.mdc` captures this as a design
rule for new code.

---

## Deprecate / yank `mcs-drivers-core` on PyPI

**Affects:** PyPI

**Status:** Open

**Problem:**
An earlier version was published under the name `mcs-drivers-core` (plural).
The canonical name is now `mcs-driver-core` (singular, consistent with the
`mcs-driver-<capability>` naming convention). The old package should be
yanked or updated with a deprecation notice pointing to `mcs-driver-core`.

---

## Hook-System für den Tool-Call-Lebenszyklus evaluieren

**Affects:** `mcs-driver-core` (ToolDriver/Orchestrator-Ebene), alle Treiber, Clients

**Status:** Open / Idee -- in ausführlicher Session evaluieren

**Problem:**
Aktuell ermitteln Clients Fähigkeiten der Treiber über **Mixins** und
`isinstance`-Checks (z.B. `ToolCallSignalingMixin`, `SupportsHealthcheck`,
`SupportsDriverContext` in `packages/core/src/mcs/driver/core/mixins/`).
Verhalten rund um einen Tool-Call (Vorab-Validierung, Permission-Abfrage,
Nachbearbeitung des Ergebnisses) ist mehr oder weniger über **Signale und
Interfaces** verteilt realisiert.

Das funktioniert, ist aber fragmentiert: Jede neue Quereinwirkung
(Logging, Permission, Argument-Patching, Audit, Retry) braucht ein eigenes
Interface bzw. Mixin, und der Client muss jede Capability einzeln abfragen.

**Idee:**
Ein einheitliches, **event-basiertes Hook-System**, in das man vor/nach
einem Tool-Call Logik injizieren kann -- statt für jede Quereinwirkung ein
neues Interface zu definieren. Der vom User skizzierte Lebenszyklus:

```
PreToolUse-Hook            -- vor dem Call; darf blocken / Argumente patchen
PermissionRequest-Hook     -- Freigabe anfragen (allow / deny / ask)
   ↓
Tool Execution
   ↓
PostToolUse-Hook           -- Ergebnis nachbearbeiten / modifizieren
PostToolUseFailure-Hook    -- Fehlerfall separat behandeln
PostToolBatch-Hook         -- nach einem ganzen Tool-Call-Batch eines Turns
```

**Referenz -- PI (earendil-works/pi):**
PI nutzt genau so ein Modell: `pi.on(eventName, async (event, ctx) => {...})`.
Relevante Events, die unsere Punkte direkt abbilden:

- **`tool_call`** -- feuert vor der Ausführung. **Kann blocken** über
  `return { block: true, reason }`. `event.input` ist **mutierbar** →
  Argument-Patching. (= unser *PreToolUse* + Permission-Deny)
- **`tool_execution_start` / `_update` / `_end`** -- reine
  Lifecycle-Notifications (Observability, Progress).
- **`tool_result`** -- feuert nach Ausführung, **kann das Ergebnis
  modifizieren**; Patches mehrerer Handler chainen. (= unser *PostToolUse*,
  inkl. `isError` für *PostToolUseFailure*)
- **`context`** -- vor jedem LLM-Call, Messages non-destruktiv anpassbar
  (relevant fürs Tool-Injection/Orchestrator-Thema).
- **`before_agent_start` / `turn_start` / `turn_end`** -- Turn-Grenzen
  (= Aufhänger für *PostToolBatch*).

PI hat keinen eigenständigen `PermissionRequest`-Event -- Permission wird
dort als Deny-Entscheidung **innerhalb** von `tool_call` modelliert. Für MCS
zu klären: eigener Hook (allow/deny/ask mit Remember-Flag, vgl. PIs
`project_trust`) vs. Spezialfall des PreToolUse.

**Zu evaluieren:**
- Hook-Registrierung: zentrale Registry / Bus vs. pro-Treiber-Hooks. Wer
  besitzt den Bus -- Orchestrator, Driver-Core, oder der Client?
- Rückgabe-Semantik: `block`, `modify`, `replace`, `continue` -- wie chainen
  mehrere Hooks (Reihenfolge, Veto-Gewinner)?
- Verhältnis zu den bestehenden Mixins: Hooks **ersetzen** Signaling-Mixins
  oder **ergänzen** sie? Capability-Detection (`isinstance`) bleibt für
  "kann der Treiber X" sinnvoll; Hooks sind eher für "tu X um den Call herum".
- Sync vs. async Hooks (vgl. CredentialProvider-Frage).
- Was davon sollte als **Standard-Hook im Treiber** mitgeliefert werden,
  damit ein Client es out-of-the-box nutzen kann (Logging-Hook,
  Permission-Hook, Audit-Hook)?
- Sicherheit: Hooks dürfen Argumente mutieren → Audit/Trust-Modell nötig
  (PI knüpft Hook-Ausführung an `isProjectTrusted()`).

**Bezug zu bestehenden TODOs:**
- *Observability* (INFO-Logging je Layer-Übergang) wäre ein natürlicher
  erster Hook-Konsument.
- *CredentialProvider* (sync/async-Frage) überschneidet sich mit der
  Hook-Signatur-Entscheidung.

**Referenzen:**
- PI Coding Agent: https://pi.dev/ ·
  https://github.com/earendil-works/pi/tree/main/packages/coding-agent
- Hook/Event-Doku: `packages/coding-agent/docs/extensions.md`
