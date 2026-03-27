#!/usr/bin/env python3
"""
MCS Skill Generator
===================

Generates a complete Agent Skill (SKILL.md + wrapper script) from any
MCS driver.  Every driver exposes ``list_tools()`` -- same interface,
same generator.

Usage (simple driver):
    python skill_generator.py "mcs.driver.filesystem:FilesystemDriver" \\
        --kwargs '{"adapter": "localfs", "base_dir": "."}' \\
        --skill-name mcs-filesystem

Usage (auth-aware driver):
    python skill_generator.py "mcs.driver.mail:MailDriver" \\
        --kwargs '{"read_adapter": "gmail", "send_adapter": "gmail"}' \\
        --skill-name mcs-gmail \\
        --auth-method auth0-linkauth \\
        --auth-params '{"auth0_domain": "", "auth0_client_id": "", ...}'

Output:
    <skill-name>/
    ├── SKILL.md
    ├── config.toml.example
    ├── .env.example
    ├── .gitignore
    └── scripts/
        └── mcs_tool.py
"""

import argparse
import importlib
import json
import os
import sys
import textwrap
from datetime import datetime

try:
    from mcs.driver.core import MCSToolDriver
except ImportError:
    print("pip install mcs-driver-core")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Resolver template (embedded verbatim in every generated script)
# ---------------------------------------------------------------------------

RESOLVER_TEMPLATE = '''\
from pathlib import Path as _Path

_SKILL_DIR = _Path(__file__).resolve().parent.parent


def _resolve(name: str, *, env_prefix: str = "{env_prefix}", secret: bool = False) -> str:
    """Resolve a config parameter: env var -> skill-local config -> interactive prompt."""
    import os, sys

    env_key = f"{{env_prefix}}_{{name.upper()}}"
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
            return getpass.getpass(f"{{name}}: ")
        return input(f"{{name}}: ")

    raise LookupError(
        f"Missing config '{{name}}'. "
        f"Set {{env_key}} or add to {{_SKILL_DIR}}/config.toml"
    )


def _load_toml(path: _Path) -> dict:
    import tomllib
    with open(path, "rb") as f:
        return tomllib.load(f)


def _load_json(path: _Path) -> dict:
    import json as _json
    with open(path) as f:
        return _json.load(f)
'''

# ---------------------------------------------------------------------------
# Auth-chain code templates  (inserted after the resolver in the script)
# ---------------------------------------------------------------------------

AUTH_CHAIN_TEMPLATES: dict[str, str] = {
    "none": "",

    "static": '''\
from mcs.auth.static import StaticProvider

_credential = StaticProvider({{
    "default": _resolve("access_token", secret=True),
}})
''',

    "auth0": '''\
from mcs.auth.auth0 import Auth0Provider
from mcs.types.cache import FileCacheStore

_credential = Auth0Provider(
    domain=_resolve("auth0_domain"),
    client_id=_resolve("auth0_client_id"),
    client_secret=_resolve("auth0_client_secret", secret=True),
    refresh_token=_resolve("auth0_refresh_token", secret=True),
    _token_cache=FileCacheStore(_SKILL_DIR / ".mcs_token_cache"),
)
''',

    "auth0-linkauth": '''\
from mcs.auth.auth0 import Auth0Provider
from mcs.auth.linkauth import LinkAuthConnector
from mcs.types.cache import FileCacheStore

_auth_connector = LinkAuthConnector(
    broker_url=_resolve("linkauth_broker_url"),
    api_key=_resolve("linkauth_api_key", secret=True) or None,
    oauth_provider="auth0",
    oauth_scopes=["openid", "email", "offline_access"],
    oauth_extra_params={{
        "audience": _resolve("auth0_audience"),
        "connection": "google-oauth2",
    }},
    display_name="{skill_name} via Auth0",
)

_credential = Auth0Provider(
    domain=_resolve("auth0_domain"),
    client_id=_resolve("auth0_client_id"),
    client_secret=_resolve("auth0_client_secret", secret=True),
    _auth=_auth_connector,
    _token_cache=FileCacheStore(_SKILL_DIR / ".mcs_token_cache"),
)
''',

    "linkauth": '''\
from mcs.auth.linkauth import LinkAuthProvider
from mcs.types.cache import FileCacheStore

_credential = LinkAuthProvider(
    broker_url=_resolve("linkauth_broker_url"),
    api_key=_resolve("linkauth_api_key", secret=True),
    template=_resolve("linkauth_template"),
    display_name="{skill_name}",
    _token_cache=FileCacheStore(_SKILL_DIR / ".mcs_token_cache"),
)
''',
}

# Default auth params per method (used for config examples)
AUTH_DEFAULT_PARAMS: dict[str, dict[str, str]] = {
    "none": {},
    "static": {"access_token": ""},
    "auth0": {
        "auth0_domain": "your-tenant.us.auth0.com",
        "auth0_client_id": "",
        "auth0_client_secret": "",
        "auth0_refresh_token": "",
    },
    "auth0-linkauth": {
        "auth0_domain": "your-tenant.us.auth0.com",
        "auth0_client_id": "",
        "auth0_client_secret": "",
        "auth0_audience": "",
        "linkauth_broker_url": "https://broker.linkauth.io",
        "linkauth_api_key": "",
    },
    "linkauth": {
        "linkauth_broker_url": "http://127.0.0.1:8080",
        "linkauth_api_key": "",
        "linkauth_template": "api_key",
    },
}


def _env_prefix(skill_name: str) -> str:
    """Derive the env-var prefix from a skill name.

    ``mcs-gmail`` → ``MCS_GMAIL``  (strips redundant ``mcs-`` prefix)
    ``my-tool``   → ``MCS_MY_TOOL``
    """
    bare = skill_name.removeprefix("mcs-") if skill_name.startswith("mcs-") else skill_name
    return "MCS_" + bare.upper().replace("-", "_")


def import_class(dotted_path: str):
    if ":" in dotted_path:
        mod_path, cls_name = dotted_path.rsplit(":", 1)
    else:
        mod_path, cls_name = dotted_path.rsplit(".", 1)
    mod = importlib.import_module(mod_path)
    return getattr(mod, cls_name)


def _collect_pip_requirements(
    driver_path: str,
    auth_method: str = "none",
    kwargs: dict | None = None,
) -> str:
    """Build a complete ``pip install`` line from installed package metadata."""
    import importlib.metadata as _meta
    import re

    mod_path = driver_path.rsplit(":", 1)[0]

    pkg_map = _meta.packages_distributions()
    top_level = mod_path.split(".")[0]
    candidates = pkg_map.get(top_level, [])

    driver_dist = None
    mod_as_pkg = mod_path.replace(".", "-")
    for name in candidates:
        if mod_as_pkg.startswith(name.lower()) or name.lower().startswith(mod_as_pkg):
            driver_dist = name
            break
    if driver_dist is None and candidates:
        driver_dist = candidates[0]

    def _add(pkg_name: str) -> None:
        if any(p.startswith(pkg_name) for p in packages):
            return
        try:
            ver = _meta.distribution(pkg_name).metadata["Version"]
            packages.append(f"{pkg_name}>={ver}")
        except _meta.PackageNotFoundError:
            packages.append(pkg_name)

    packages: list[str] = []
    extras_map: dict[str, str] = {}
    if driver_dist:
        dist = _meta.distribution(driver_dist)
        ver = dist.metadata["Version"]
        packages.append(f"{driver_dist}>={ver}")
        for req_str in (dist.requires or []):
            extra_match = re.search(r'extra\s*==\s*"(\w+)"', req_str)
            if extra_match:
                extra_name = extra_match.group(1)
                req_name = req_str.split(">")[0].split("<")[0].split("=")[0].split(";")[0].strip()
                extras_map[extra_name] = req_name
                continue
            req_name = req_str.split(">")[0].split("<")[0].split("=")[0].split(";")[0].strip()
            _add(req_name)

    # Resolve adapter packages from kwargs (e.g. adapter=localfs, read_adapter=gmail)
    if kwargs:
        adapter_names: set[str] = set()
        for key, val in kwargs.items():
            if "adapter" in key and isinstance(val, str):
                adapter_names.add(val)
        for adapter_name in adapter_names:
            if adapter_name in extras_map:
                _add(extras_map[adapter_name])
            else:
                _add(f"mcs-adapter-{adapter_name}")

    auth_packages: dict[str, list[str]] = {
        "none": [],
        "static": ["mcs-auth"],
        "auth0": ["mcs-auth", "mcs-auth-auth0", "mcs-types-cache"],
        "auth0-linkauth": ["mcs-auth", "mcs-auth-auth0", "mcs-auth-linkauth", "mcs-types-cache"],
        "linkauth": ["mcs-auth", "mcs-auth-linkauth", "mcs-types-cache"],
    }
    for pkg in auth_packages.get(auth_method, []):
        _add(pkg)

    return "pip install " + " ".join(packages) if packages else "pip install mcs-driver-core"


def generate_skill_md(
    driver,
    skill_name: str,
    driver_path: str,
    auth_method: str = "none",
    all_params: dict | None = None,
    kwargs: dict | None = None,
) -> str:
    """Generate a complete SKILL.md from a live driver instance."""
    meta = driver.meta
    tools = driver.list_tools()
    env_prefix = _env_prefix(skill_name)

    tool_names = ", ".join(t.name for t in tools)
    domain = meta.name.lower().replace(" mcs driver", "")

    desc_lines = [
        f"  Provides {domain} tools: {tool_names}.",
    ]
    for t in tools:
        if t.description:
            first_sentence = t.description.strip().split(".")[0]
            desc_lines.append(f"  - {t.name}: {first_sentence}.")
    desc_lines.append(f"  Use when the user asks about {domain} operations.")

    lines = [
        "---",
        f"name: {skill_name}",
        "description: >",
        *desc_lines,
        "allowed-tools: Bash(python *) Bash(pip *) Bash(uv *) Read",
        "---",
        "",
        f"# {meta.name}",
        "",
    ]

    # --- Configuration section ---
    if all_params:
        lines.extend([
            "## Configuration",
            "",
            "Before using this skill, configure the required parameters.",
            "The wrapper script resolves each parameter in order:",
            "",
            "1. **Environment variable** (highest priority)",
            "2. **Config file** (`config.toml` or `config.json` in the skill directory)",
            "3. **Interactive prompt** (only in a terminal session)",
            "",
            "### Option A: Config file",
            "",
            f"Copy `config.toml.example` to `config.toml` in the skill directory and fill in the values.",
            "",
            "### Option B: Environment variables",
            "",
        ])
        for param in all_params:
            env_key = f"{env_prefix}_{param.upper()}"
            lines.append(f"- `{env_key}`")
        lines.extend(["", "### Parameters", ""])
        lines.append("| Parameter | Env Variable | Description |")
        lines.append("|-----------|-------------|-------------|")
        for param, default in all_params.items():
            env_key = f"{env_prefix}_{param.upper()}"
            is_secret = "secret" in param.lower() or "token" in param.lower() or "key" in param.lower()
            desc = "(secret)" if is_secret else ""
            lines.append(f"| `{param}` | `{env_key}` | {desc} |")
        lines.append("")

    # --- Setup section ---
    lines.extend([
        "## Setup",
        "",
        "```bash",
        _collect_pip_requirements(driver_path, auth_method, kwargs),
        "```",
        "",
        "## Tools",
        "",
    ])

    # --- Tool documentation ---
    for tool in tools:
        lines.append(f"### {tool.name}")
        lines.append("")
        if tool.description:
            lines.append(tool.description)
            lines.append("")

        if tool.parameters:
            lines.append("| Parameter | Required | Description |")
            lines.append("|-----------|----------|-------------|")
            for p in tool.parameters:
                req = "yes" if p.required else "no"
                desc = p.description or ""
                lines.append(f"| `{p.name}` | {req} | {desc} |")
            lines.append("")

        example_params = {}
        for p in tool.parameters:
            if p.required:
                example_params[p.name] = f"<{p.name}>"
        params_str = json.dumps(example_params)

        lines.append("```bash")
        lines.append(
            f"python ${{CLAUDE_SKILL_DIR}}/scripts/mcs_tool.py exec {tool.name} '{params_str}'"
        )
        lines.append("```")
        lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines)


def generate_config_example(all_params: dict) -> str:
    """Generate a config.toml.example file."""
    lines = ["# MCS Skill Configuration", "# Copy this file to config.toml and fill in the values.", ""]
    for param, default in all_params.items():
        is_secret = "secret" in param.lower() or "token" in param.lower() or "key" in param.lower()
        if is_secret:
            lines.append(f'# {param} = ""  # secret -- consider using env var instead')
        elif default:
            lines.append(f'{param} = "{default}"')
        else:
            lines.append(f'{param} = ""')
    return "\n".join(lines) + "\n"


def generate_env_example(skill_name: str, all_params: dict) -> str:
    """Generate a .env.example file."""
    env_prefix = _env_prefix(skill_name)
    lines = [f"# Environment variables for {skill_name}", f"# Prefix: {env_prefix}_*", ""]
    for param in all_params:
        env_key = f"{env_prefix}_{param.upper()}"
        lines.append(f"{env_key}=")
    return "\n".join(lines) + "\n"


def generate_gitignore() -> str:
    """Generate a .gitignore that protects credential and cache files."""
    return "config.toml\nconfig.json\n.env\n.mcs_token_cache\n"


def generate_script(
    driver_path: str,
    kwargs: dict,
    skill_name: str,
    auth_method: str = "none",
    auth_params: dict | None = None,
    credential_kwargs: list[str] | None = None,
) -> str:
    """Generate the wrapper script with hybrid credential resolution."""
    mod_path, cls_name = driver_path.rsplit(":", 1)
    env_prefix = _env_prefix(skill_name)
    credential_kwargs = credential_kwargs or []

    resolver_block = RESOLVER_TEMPLATE.format(env_prefix=env_prefix)
    auth_chain = AUTH_CHAIN_TEMPLATES.get(auth_method, "")
    auth_chain = auth_chain.format(skill_name=skill_name)

    has_resolvable = any(
        "adapter" not in k and k not in credential_kwargs
        for k in kwargs
    ) or bool(auth_params)

    driver_args_parts = []
    for k, v in kwargs.items():
        if k in credential_kwargs:
            continue
        if "adapter" in k:
            driver_args_parts.append(f'    {k}="{v}",')
        else:
            is_secret = "secret" in k.lower() or "token" in k.lower() or "key" in k.lower()
            secret_flag = ", secret=True" if is_secret else ""
            driver_args_parts.append(f'    {k}=_resolve("{k}"{secret_flag}),')

    if auth_method != "none":
        if credential_kwargs:
            for ck in credential_kwargs:
                driver_args_parts.append(f'    {ck}={{"_credential": _credential}},')
        else:
            driver_args_parts.append("    _credential=_credential,")
    driver_args = "\n".join(driver_args_parts)

    parts = [
        '#!/usr/bin/env python3',
        '"""Auto-generated MCS skill script. Do not edit -- regenerate instead."""',
        '',
        'import json',
        'import sys',
        '',
        f'try:',
        f'    from {mod_path} import {cls_name}',
        f'except ImportError:',
        f'    print(json.dumps({{"error": "Driver not installed. pip install ..."}}))' ,
        f'    sys.exit(1)',
        '',
    ]

    if has_resolvable:
        parts.extend([
            '',
            '# --- Config resolution (env -> config.toml/json -> prompt) ---',
            '',
            resolver_block,
        ])

    if auth_method != "none":
        parts.extend([
            '',
            f'# --- Auth chain ({auth_method}) ---',
            '',
            auth_chain,
        ])

    parts.extend([
        '',
        '# --- Driver ---',
        '',
        f'driver = {cls_name}(',
        driver_args,
        ')',
        '',
        '',
        'def _run_cli():',
        '    if len(sys.argv) < 2:',
        '        print("Usage: mcs_tool.py [status|tools|exec <name> \'<json>\']")',
        '        sys.exit(1)',
        '',
        '    cmd = sys.argv[1]',
        '',
        '    if cmd == "status":',
        '        tools = driver.list_tools()',
        '        print(json.dumps({',
        '            "driver": driver.meta.name,',
        '            "version": driver.meta.version,',
        '            "tools": [t.name for t in tools],',
        '        }, indent=2))',
        '',
        '    elif cmd == "tools":',
        '        for t in driver.list_tools():',
        '            print(f"{t.name}: {t.description}")',
        '            for p in t.parameters:',
        '                req = "(required)" if p.required else "(optional)"',
        '                print(f"  {p.name} {req}: {p.description}")',
        '',
        '    elif cmd == "exec":',
        '        name = sys.argv[2]',
        '        params = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}',
        '        result = driver.execute_tool(name, params)',
        '        if isinstance(result, (dict, list)):',
        '            print(json.dumps(result, indent=2, ensure_ascii=False))',
        '        else:',
        '            print(result)',
        '',
        '    else:',
        '        print(f"Unknown command: {cmd}")',
        '        sys.exit(1)',
        '',
        '',
        'if __name__ == "__main__":',
        '    _run_cli()',
        '',
    ])

    return "\n".join(parts)


def main():
    parser = argparse.ArgumentParser(
        description="MCS Skill Generator -- generates Agent Skills from MCS drivers",
    )
    parser.add_argument(
        "driver",
        help="Driver class path, e.g. mcs.driver.filesystem:FilesystemDriver",
    )
    parser.add_argument(
        "--kwargs", default="{}",
        help="JSON dict of driver constructor kwargs (resolved at runtime via _resolve())",
    )
    parser.add_argument("--skill-name", required=True, help="Skill name (lowercase, hyphens)")
    parser.add_argument("--output", default=None, help="Output directory (default: ./<skill-name>)")
    parser.add_argument(
        "--auth-method", default="none",
        choices=list(AUTH_CHAIN_TEMPLATES.keys()),
        help="Authentication method to wire into the generated script",
    )
    parser.add_argument(
        "--auth-params", default=None,
        help="JSON dict of auth parameter overrides (merged with defaults for the auth method)",
    )
    parser.add_argument(
        "--credential-kwargs", default=None,
        help='Comma-separated driver kwargs that receive {"_credential": _credential} '
             '(e.g. "read_kwargs,send_kwargs"). If omitted, _credential is injected as top-level kwarg.',
    )

    args = parser.parse_args()
    kwargs = json.loads(args.kwargs)
    output_dir = args.output or f"./{args.skill_name}"
    credential_kwargs = (
        [k.strip() for k in args.credential_kwargs.split(",")]
        if args.credential_kwargs else []
    )

    # Merge auth params: defaults + user overrides
    auth_params = dict(AUTH_DEFAULT_PARAMS.get(args.auth_method, {}))
    if args.auth_params:
        auth_params.update(json.loads(args.auth_params))

    # Adapter-selection keys (structural) are baked in at generation time.
    # All other kwargs are config params, resolvable at runtime just like auth params.
    def _is_adapter_key(k: str) -> bool:
        return "adapter" in k

    baked_kwargs = {k: v for k, v in kwargs.items()
                    if _is_adapter_key(k) or k in credential_kwargs}
    config_kwargs = {k: v for k, v in kwargs.items()
                     if not _is_adapter_key(k) and k not in credential_kwargs}
    all_params = {**config_kwargs, **auth_params}

    # Import and instantiate driver for tool discovery.
    # Auth-aware drivers need a dummy credential to instantiate;
    # the generated script will use the real auth chain at runtime.
    DriverClass = import_class(args.driver)
    discovery_kwargs = dict(kwargs)
    if args.auth_method != "none":
        _dummy_cred = {"access_token": "__discovery_dummy__"}
        for ck in credential_kwargs:
            discovery_kwargs[ck] = _dummy_cred
    driver = DriverClass(**discovery_kwargs)

    tools = driver.list_tools()
    print(f"Driver:      {driver.meta.name} v{driver.meta.version}")
    print(f"Tools:       {[t.name for t in tools]}")
    print(f"Auth method: {args.auth_method}")
    print(f"Parameters:  {list(all_params.keys())}")

    # Generate all files
    skill_md = generate_skill_md(
        driver, args.skill_name, args.driver, args.auth_method, all_params, kwargs,
    )
    script = generate_script(
        args.driver, kwargs, args.skill_name, args.auth_method, auth_params,
        credential_kwargs,
    )

    # Write outputs
    os.makedirs(os.path.join(output_dir, "scripts"), exist_ok=True)

    files_to_write = {
        "SKILL.md": skill_md,
        os.path.join("scripts", "mcs_tool.py"): script,
        ".gitignore": generate_gitignore(),
    }

    if all_params:
        files_to_write["config.toml.example"] = generate_config_example(all_params)
        files_to_write[".env.example"] = generate_env_example(args.skill_name, all_params)

    for rel_path, content in files_to_write.items():
        full_path = os.path.join(output_dir, rel_path)
        with open(full_path, "w") as f:
            f.write(content)
        print(f"  Written: {full_path}")

    print(f"\nSkill generated in {output_dir}/")
    print(f"Test with: python {os.path.join(output_dir, 'scripts', 'mcs_tool.py')} status")


if __name__ == "__main__":
    main()
