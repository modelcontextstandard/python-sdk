# mcs-auth-linkauth

**Authentication for agents that can't open a browser.** LinkAuth credential
broker adapter for the **Model Context Standard (MCS)**.

CLI tools, Telegram bots, background workers, Docker containers -- your
agent shows a URL and a code, the user authenticates on any device, and the
agent picks up the credentials automatically. No localhost callback. No
web server. No browser on the agent's machine.

Think of it as the Device Flow experience, but for *any* credential type --
OAuth tokens, API keys, passwords, or custom secrets.

## Installation

```bash
pip install mcs-auth-linkauth
```

## Quick start

```python
from mcs.auth.linkauth import LinkAuthProvider

provider = LinkAuthProvider(
    broker_url="https://auth.example.com",
    template="google_mail",
    display_name="Gmail Access",
)

try:
    token = provider.get_token("gmail")
except AuthChallenge as e:
    # Show this to the user via LLM, Telegram, CLI, ...
    print(f"Open {e.url} and enter code {e.code}")
```

## How it works

```
Agent                     LinkAuth Broker              User
  |                            |                        |
  |-- create session --------->|                        |
  |   (public_key, template)   |                        |
  |<-- url + code ------------|                        |
  |                            |                        |
  |-- raise AuthChallenge ---->|                        |
  |   "Open URL, enter ABCD"  |                        |
  |                            |<-- user opens URL -----|
  |                            |    enters code         |
  |                            |    provides credentials|
  |                            |    (encrypted w/ pubkey)|
  |                            |                        |
  |-- poll ------------------->|                        |
  |<-- encrypted credentials --|                        |
  |-- decrypt (private key) -->|                        |
  |                            |                        |
  | token ready!               |                        |
```

**Zero-knowledge:** For form-based credentials (API keys, passwords), the
broker encrypts with the agent's public key in the browser. The broker
never sees the plaintext. For OAuth flows, the broker briefly handles
tokens server-side before encrypting -- a documented trade-off.

## Use with Auth0 Token Vault

The killer combo -- LinkAuth's device-flow UX with Auth0's multi-provider
Token Vault:

```python
from mcs.auth.auth0 import Auth0Provider
from mcs.auth.linkauth import LinkAuthAdapter

provider = Auth0Provider(
    domain="my-tenant.auth0.com",
    client_id="...",
    client_secret="...",
    _auth=LinkAuthAdapter(
        broker_url="https://auth.example.com",
        oauth_provider="auth0",
        oauth_scopes=["openid", "email", "offline_access"],
        oauth_extra_params={"audience": "...", "connection": "google-oauth2"},
        display_name="Gmail Access",
    ),
)

# Agent shows URL + code, user authenticates, Token Vault does the rest
token = provider.get_token("gmail")
```

## Supported credential types

| Template | What the user sees |
|---|---|
| `api_key` | Single password field |
| `basic_auth` | Username + password form |
| `openai`, `anthropic` | Branded API key form |
| `google_mail`, `github`, ... | OAuth consent flow |
| Custom | Define your own fields or OAuth provider |

## Links

- **Homepage:** <https://www.modelcontextstandard.io>
- **Source:** <https://github.com/modelcontextstandard/python-sdk>
- **LinkAuth:** <https://github.com/user/linkauth>

## License

Apache-2.0
