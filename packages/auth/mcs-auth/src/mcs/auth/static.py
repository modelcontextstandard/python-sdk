"""Static credential provider -- tokens from a dict or environment variables.

Useful for local development, testing, and simple deployments where
tokens are known upfront or stored in environment variables.
"""

from __future__ import annotations

import os


class StaticProvider:
    """Credential provider backed by a plain dictionary.

    Parameters
    ----------
    tokens :
        Mapping of scope → token value.  When a scope is not found
        in *tokens*, the provider falls back to the environment
        variable ``MCS_TOKEN_<SCOPE>`` (upper-cased, hyphens replaced
        with underscores).
    """

    def __init__(self, tokens: dict[str, str] | None = None) -> None:
        self._tokens: dict[str, str] = dict(tokens or {})

    def get_token(self, scope: str) -> str:
        """Return a token for *scope* from the dict or environment."""
        if scope in self._tokens:
            return self._tokens[scope]

        env_key = f"MCS_TOKEN_{scope.upper().replace('-', '_').replace('.', '_')}"
        env_val = os.environ.get(env_key)
        if env_val:
            return env_val

        raise LookupError(
            f"No credential for scope {scope!r}.  "
            f"Provide it via StaticProvider(tokens={{...}}) or set {env_key}."
        )
