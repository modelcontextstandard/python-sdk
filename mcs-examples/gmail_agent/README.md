# MCS Gmail Agent

Interactive chat agent that reads and sends e-mail via the Gmail API,
powered by the Model Context Standard.

## Architecture

```
LLM (GPT-4o / Claude / ...)
 │
 MailDriver                    ← composite driver (read + send)
 ├── MailreadToolDriver        ← 7 tools (list, fetch, search, move, ...)
 │   └── GmailAdapter          ← Gmail REST API
 └── MailsendToolDriver        ← 2 tools (send plain, send HTML)
     └── GmailAdapter          ← Gmail REST API
         └── HttpAdapter        ← HTTP transport (swappable)
             │
         CredentialProvider     ← Auth0 Token Vault / static token
```

## Quick start

```bash
# Install dependencies
pip install mcs-driver-mail[gmail] mcs-auth-auth0 litellm rich python-dotenv

# Copy and fill in .env
cp .env.example .env

# Run with a static Google OAuth2 token (for testing):
python main.py --token ya29.xxx

# Run with Auth0 Token Vault:
python main.py --auth0

# Custom model + debug output:
python main.py --auth0 --model anthropic/claude-sonnet-4-20250514 --debug
```

## Auth modes

| Mode | Flag | Credential source |
|------|------|-------------------|
| Static token | `--token ya29.xxx` | Google OAuth Playground or gcloud CLI |
| Auth0 | `--auth0` | Auth0 Token Vault (env vars) |

## Available tools

The agent has access to 9 e-mail tools:

**Read (7):** `list_folders`, `list_messages`, `fetch_message`, `search_messages`,
`move_message`, `set_flags`, `create_folder`

**Send (2):** `send_message`, `send_html_message`
