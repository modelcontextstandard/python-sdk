# mcs-auth-oauth

**OAuth 2.0 for AI agents.** Authorization Code Flow with PKCE connector
for the **Model Context Standard (MCS)**.

A 5-second localhost callback server and your agent has an OAuth token.
Works with any OAuth 2.0 provider -- Google, Auth0, Microsoft, GitHub,
you name it.

## Installation

```bash
pip install mcs-auth-oauth
```

## Quick start

```python
from mcs.auth.oauth import OAuthProvider

provider = OAuthProvider(
    authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
    token_url="https://oauth2.googleapis.com/token",
    client_id="...",
    client_secret="...",
    scopes={"gmail": "https://mail.google.com/"},
)

# Opens browser, user logs in, token returned
token = provider.get_token("gmail")
```

## How it works

1. Agent calls `get_token("gmail")`
2. Browser opens with the provider's consent screen
3. User logs in and grants access
4. Localhost callback receives the authorization code
5. Code is exchanged for tokens (with PKCE)
6. Token returned to agent -- done

The entire flow happens in a single `get_token()` call. The localhost
server lives for exactly one request and shuts down immediately.

## Use with Auth0 Token Vault

```python
from mcs.auth.auth0 import Auth0Provider
from mcs.auth.oauth import OAuthConnector

provider = Auth0Provider(
    domain="my-tenant.auth0.com",
    client_id="...",
    client_secret="...",
    _auth=OAuthConnector(
        authorize_url="https://my-tenant.auth0.com/authorize",
        token_url="https://my-tenant.auth0.com/oauth/token",
        client_id="...",
        client_secret="...",
        extra_params={"connection": "google-oauth2", "audience": "..."},
    ),
)
```

## Links

- **Homepage:** <https://www.modelcontextstandard.io>
- **Source:** <https://github.com/modelcontextstandard/python-sdk>

## License

Apache-2.0
