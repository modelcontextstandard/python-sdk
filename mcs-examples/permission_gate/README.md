# Permission Gate Example

Every tool call stops and asks the user first. Answer `y` and it runs; answer
anything else and it does not.

```bash
python chat.py                  # streaming (default)
python chat.py --no-stream      # one assembled response per turn
python chat.py --debug          # + system prompt, raw output, DriverResponse
python chat.py --allow-all      # answers the gate automatically -- still shows every call
```

```
You: search for MCS repositories

⠹ a tool call is forming...
╭─ Tool call requested ───────────────────╮
│ search_repos(q='MCS', sort='stars')     │
╰─────────────────────────────────────────╯
Allow? [y/N] n
-> denied

Assistant: Verstanden -- ich habe die Suche nicht ausgeführt.
```

While the answer is on its way a spinner reports what is happening -- first
`waiting for the model`, then `a tool call is forming` once the driver
recognises one. Nothing half-written is ever printed, so there is no raw JSON to
scrub off the screen afterwards.

## What it shows

**The gate is middleware, not client code.** `PermissionMiddleware` sits *inside*
the driver and wraps `execute_tool`. It gets the pending call with its arguments,
asks a consent handler, and then either continues the chain or short-circuits it:

```python
driver = RestDriver(url=spec_url)
driver.add_middleware(PermissionMiddleware(consent_handler=view.ask_consent))
```

That is the entire integration. Compare `chat.py` with the other examples --
the chat loop is byte-for-byte the same `ChatSession` call. Consent is
**configuration of a driver**, not a branch in the application.

**A denial is an answer, not an error.** The middleware returns a structured
`{"permission_denied": true, ...}` result instead of raising, so the model reads
the refusal like any other tool result and can respond to it ("understood, I did
not run that"). Nothing is executed, and the conversation stays well-formed --
which matters, because a provider expects a result for every tool call it made.

**It behaves identically while streaming.** The middleware runs inside
`process_llm_response`, so the prompt appears mid-stream at the moment the driver
is about to execute -- and the answer resumes underneath it afterwards. The
consent handler is the *view*, because it owns the terminal and knows whether it
is mid-line.

**`--allow-all` does not switch the gate off**, it answers it automatically. The
pending call is still printed, just followed by `-> auto-approved` instead of a
prompt. That is the honest contrast: the middleware is in the chain either way,
only its answer differs.

## Where this fits

| Concern | Mechanism |
|---|---|
| Ask before executing | `PermissionMiddleware` (this example) |
| Handle an auth challenge | `AuthMiddleware` -- turns it into an in-band result with a login URL |
| Observe the lifecycle | `HooksMiddleware` -- pre / post / on-failure callbacks |

All three are `ToolMiddleware`, all three are passed to the driver the same way,
and their order is list order, outermost first. See
[ADR-0002](https://modelcontextstandard.io/docs/adr/0002-tool-middleware-over-decorators).

## Requires

```bash
pip install mcs-driver-rest mcs-permission litellm rich python-dotenv
export OPENAI_API_KEY=sk-...
```
