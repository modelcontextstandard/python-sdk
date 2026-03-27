# mcs-auth-auth0

**One credential. Every service.** Auth0 Token Vault integration for the
**Model Context Standard (MCS)**.

Configure Gmail, Google Drive, Slack, GitHub, and Microsoft connections
once in the Auth0 dashboard. Your agent accesses all of them through a
single `get_token(scope)` call. No separate OAuth clients, no per-service
credential management, no token refresh headaches.

## Installation

```bash
pip install mcs-auth-auth0
```

## Quick start

```python
from mcs.auth.auth0 import Auth0Provider

provider = Auth0Provider(
    domain="my-tenant.auth0.com",
    client_id="...",
    client_secret="...",
    refresh_token="...",  # from auth setup or AuthPort connector
)

# One call -- Auth0 handles the Token Vault exchange (RFC 8693)
google_token = provider.get_token("gmail")
slack_token = provider.get_token("slack")
github_token = provider.get_token("github")
```

## How it works

```
Your Agent                  Auth0 Token Vault         External Provider
    |                            |                          |
    |-- get_token("gmail") ----->|                          |
    |                            |-- RFC 8693 exchange ---->|
    |                            |<--- Google access token -|
    |<-- "ya29.a0..." ----------|                          |
```

The `Auth0Provider` exchanges an Auth0 refresh token for an external
provider's access token via Token Vault. It doesn't know *how* the
refresh token was obtained -- that's pluggable via `AuthPort`:

```python
from mcs.auth.auth0 import Auth0Provider
from mcs.auth.oauth import OAuthConnector        # browser login
from mcs.auth.linkauth import LinkAuthConnector  # device-flow broker

# Browser-based login
provider = Auth0Provider(..., _auth=OAuthConnector(...))

# LinkAuth device-flow (no browser callback needed)
provider = Auth0Provider(..., _auth=LinkAuthConnector(...))
```

## Built-in scope mapping

| MCS scope | Auth0 connection |
|---|---|
| `gmail`, `google`, `google-drive`, `google-calendar` | `google-oauth2` |
| `slack` | `slack` |
| `github` | `github` |
| `microsoft` | `windowslive` |

Custom mappings: `Auth0Provider(..., connections={"myservice": "my-connection"})`

## Links

- **Homepage:** <https://www.modelcontextstandard.io>
- **Source:** <https://github.com/modelcontextstandard/python-sdk>

## License

Apache-2.0
