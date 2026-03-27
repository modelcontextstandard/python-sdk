#!/usr/bin/env python3
"""Auto-generated MCS skill script. Do not edit -- regenerate instead."""

import json
import os
import sys

# Some container environments (e.g. Claude Code Desktop) set NO_PROXY to
# include *.googleapis.com while requiring all traffic to go through the
# egress proxy.  This causes requests to bypass the proxy and fail.
for _var in ("no_proxy", "NO_PROXY"):
    _val = os.environ.get(_var, "")
    if "googleapis.com" in _val or "google.com" in _val:
        os.environ[_var] = ",".join(
            p.strip() for p in _val.split(",")
            if "googleapis.com" not in p and "google.com" not in p
        )

try:
    from mcs.driver.mail import MailDriver
except ImportError:
    print(json.dumps({"error": "Driver not installed. pip install ..."}))
    sys.exit(1)


# --- Config resolution (env -> config.toml/json -> prompt) ---

from pathlib import Path as _Path

_SKILL_DIR = _Path(__file__).resolve().parent.parent


def _resolve(name: str, *, env_prefix: str = "MCS_GMAIL", secret: bool = False) -> str:
    """Resolve a config parameter: env var -> skill-local config -> interactive prompt."""
    import os, sys

    env_key = f"{env_prefix}_{name.upper()}"
    val = os.environ.get(env_key)
    if val:
        return val

    for cfg_name, loader in [("config.toml", _load_toml), ("config.json", _load_json)]:
        cfg_path = _SKILL_DIR / cfg_name
        if cfg_path.exists():
            cfg = loader(cfg_path)
            if name in cfg:
                return cfg[name]

    if sys.stdin.isatty():
        if secret:
            import getpass
            return getpass.getpass(f"{name}: ")
        return input(f"{name}: ")

    raise LookupError(
        f"Missing config '{name}'. "
        f"Set {env_key} or add to {_SKILL_DIR}/config.toml"
    )


def _load_toml(path: _Path) -> dict:
    import tomllib
    with open(path, "rb") as f:
        return tomllib.load(f)


def _load_json(path: _Path) -> dict:
    import json as _json
    with open(path) as f:
        return _json.load(f)


# --- Auth chain (auth0-linkauth) ---

from mcs.auth.auth0 import Auth0Provider
from mcs.auth.linkauth import LinkAuthConnector
from mcs.types.cache import FileCacheStore

import os as _os
_cache_dir = _Path(_os.environ["MCS_CACHE_DIR"]) if _os.environ.get("MCS_CACHE_DIR") else _Path.home() / ".mcs" / "cache"
_token_cache = FileCacheStore(_cache_dir / "mcs-gmail.json")

_auth_connector = LinkAuthConnector(
    broker_url=_resolve("linkauth_broker_url"),
    api_key=_resolve("linkauth_api_key", secret=True) or None,
    oauth_provider="auth0",
    oauth_scopes=["openid", "email", "offline_access"],
    oauth_extra_params={
        "audience": _resolve("auth0_audience"),
        "connection": "google-oauth2",
    },
    display_name="mcs-gmail via Auth0",
    _token_cache=_token_cache,
)

_credential = Auth0Provider(
    domain=_resolve("auth0_domain"),
    client_id=_resolve("auth0_client_id"),
    client_secret=_resolve("auth0_client_secret", secret=True),
    connection_scopes={
        "gmail": [
            "https://mail.google.com/",
            "https://www.googleapis.com/auth/gmail.readonly",
            "https://www.googleapis.com/auth/gmail.send",
            "https://www.googleapis.com/auth/gmail.modify",
            "openid",
            "email",
        ],
    },
    _auth=_auth_connector,
    _token_cache=_token_cache,
)


# --- Driver ---

driver = MailDriver(
    read_adapter="gmail",
    send_adapter="gmail",
    read_kwargs={"_credential": _credential},
    send_kwargs={"_credential": _credential},
)


def _run_cli():
    if len(sys.argv) < 2:
        print("Usage: mcs_tool.py [status|tools|exec <name> '<json>']")
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "status":
        tools = driver.list_tools()
        print(json.dumps({
            "driver": driver.meta.name,
            "version": driver.meta.version,
            "tools": [t.name for t in tools],
        }, indent=2))

    elif cmd == "tools":
        for t in driver.list_tools():
            print(f"{t.name}: {t.description}")
            for p in t.parameters:
                req = "(required)" if p.required else "(optional)"
                print(f"  {p.name} {req}: {p.description}")

    elif cmd == "exec":
        name = sys.argv[2]
        params = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
        result = driver.execute_tool(name, params)
        if isinstance(result, (dict, list)):
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            print(result)

    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)


if __name__ == "__main__":
    _run_cli()
