# mcs-auth

The authentication backbone for the **Model Context Standard (MCS)**.

Stop wiring OAuth flows, API keys, and token refresh logic into every agent
you build. `mcs-auth` defines a universal `CredentialProvider` protocol --
one interface, any credential source. Your agent code never changes, no
matter how authentication works behind the scenes.

## Installation

```bash
pip install mcs-auth
```

## What's inside

| Component | What it does |
|---|---|
| `CredentialProvider` | Protocol: `get_token(scope) -> str`. Any provider satisfies it. |
| `AuthPort` | Protocol for auth transport adapters (OAuth, LinkAuth, Device Flow, ...). |
| `AuthChallenge` | Exception raised when user interaction is needed (URL + code). |
| `AuthMixin` | Mixin for drivers -- catches auth challenges at the tool execution boundary. |
| `StaticProvider` | Simple provider: tokens from a dict or environment variables. |

## Quick start

```python
from mcs.auth.static import StaticProvider

# From a dict
provider = StaticProvider(tokens={"gmail": "ya29.xxx", "openai": "sk-xxx"})
token = provider.get_token("gmail")

# From environment variables (MCS_TOKEN_GMAIL, MCS_TOKEN_OPENAI, ...)
provider = StaticProvider()
token = provider.get_token("gmail")
```

## The big picture

Your agent calls `provider.get_token("gmail")`. Where that token comes from
is none of the agent's business:

```
CredentialProvider.get_token("gmail")
  |
  +-- StaticProvider          (env vars, dicts)
  +-- Auth0Provider           (Token Vault exchange)  --> mcs-auth-auth0
  +-- OAuthProvider           (browser login)         --> mcs-auth-oauth
  +-- LinkAuthProvider        (device-flow broker)    --> mcs-auth-linkauth
```

Swap providers without touching agent code. Add new services without new
OAuth integrations. That's the power of a protocol-based auth layer.

## Links

- **Homepage:** <https://www.modelcontextstandard.io>
- **Source:** <https://github.com/modelcontextstandard/python-sdk>

## License

Apache-2.0
