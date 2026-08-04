# MCS Gmail Agent

Interactive chat agent that reads and sends e-mail via the Gmail API,
powered by the Model Context Standard.

This is the example where all three cross-cutting concerns run at once -- and the
interesting one is **auth**.

## Architecture

```
LLM (GPT-5 / Claude / ...)
 │
 MailDriver                    ← composite driver (read + send)
 │   middleware chain, outermost first:
 │   ├── PermissionMiddleware  ← asks the user before anything runs
 │   ├── HooksMiddleware       ← reports "a tool is running"
 │   └── AuthMiddleware        ← catches a credential challenge
 │
 ├── MailreadToolDriver        ← 7 tools (list, fetch, search, move, ...)
 │   └── GmailAdapter          ← Gmail REST API
 └── MailsendToolDriver        ← 2 tools (send plain, send HTML)
     └── GmailAdapter          ← Gmail REST API
         └── HttpAdapter       ← HTTP transport (swappable)
             │
         CredentialProvider    ← Auth0 Token Vault / LinkAuth / static token
```

The client sees none of this. It builds the driver, hands it to the shared
`ChatSession`, and the loop is identical to every other example.

## Why the order is Permission → Hooks → Auth

Chain order is list order, outermost first, and it carries meaning:

* **Permission outermost.** It decides whether the call happens at all. A denied
  call never runs -- so it must never announce itself as running either, which it
  would if the hook sat outside it.
* **Hooks in the middle.** Once the user has agreed, the pre-hook fires and the
  client can show progress. This is how the client learns a tool is running
  *without ever inspecting the LLM output* -- the MCS premise.
* **Auth innermost.** A credential challenge is raised at execution, so the
  handler belongs closest to it.

Measured on the real chain:

| Scenario | What actually happened |
|---|---|
| User approves | `consent → hook → execute` |
| User denies | `consent` only -- no hook, no execution |
| Approves, credentials missing | `consent → hook → execute`, challenge caught |

## What an auth challenge looks like

When a provider needs the user to log in, it raises `AuthChallenge`. Instead of
crashing the run, `AuthMiddleware` turns it into a normal tool result:

```json
{"auth_required": true, "message": "Gmail access needs to be authorised",
 "url": "https://login.example/abc", "code": "ABCD-1234", "scope": "gmail"}
```

The driver reports `call_executed=True` (something *did* happen, it just was not
the mail), and the model reads the payload like any other result -- so it can tell
the user, in its own words, where to log in. The conversation stays well-formed,
which matters because a provider expects a result for every tool call it made.

## Quick start

```bash
# Install dependencies
pip install mcs-driver-mail[gmail] mcs-auth-auth0 litellm rich python-dotenv

# Copy and fill in .env
cp .env.example .env

# Run with a static Google OAuth2 access token (for testing):
python main.py --gmail-token ya29.xxx

# Run with Auth0 pre-existing refresh token:
python main.py --auth0-token

# Custom model + debug output:
python main.py --auth0-token --model anthropic/claude-sonnet-4-20250514 --debug

# Non-streaming, or text-prompt mode instead of native tool-calling:
python main.py --auth0-token --no-stream
python main.py --auth0-token --no-native-tools
```

## Auth modes

| Mode | Flag | Credential source |
|------|------|-------------------|
| Static token | `--gmail-token ya29.xxx` | Google OAuth Playground or gcloud CLI |
| Auth0 refresh token | `--auth0-token` | Auth0 with pre-existing refresh token (env vars) |
| Auth0 browser login | `--auth0-oauth` | Authorization Code Flow via browser |
| Auth0 + LinkAuth | `--auth0-linkauth` | Device-flow via LinkAuth broker |
| LinkAuth direct | `--linkauth` | LinkAuth broker without Auth0 |

## Available tools

The agent has access to 9 e-mail tools:

**Read (7):** `list_folders`, `list_messages`, `fetch_message`, `search_messages`,
`move_message`, `set_flags`, `create_folder`

**Send (2):** `send_message`, `send_html_message`
