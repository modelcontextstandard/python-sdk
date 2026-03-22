"""MCP server configuration parser.

Parses the ``mcpServers`` JSON format used by Claude Desktop, VS Code,
and other MCP hosts into MCS adapter instances.

Example input::

    {
      "mcpServers": {
        "filesystem": {
          "command": "npx",
          "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
          "env": {"NODE_ENV": "production"}
        },
        "remote-api": {
          "url": "https://mcp.example.com/sse",
          "headers": {"Authorization": "Bearer sk-..."}
        }
      }
    }

Local servers (with ``command``) become ``MCPLocalAdapter`` instances.
Remote servers (with ``url``) become ``MCPRemoteAdapter`` instances.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Tuple, Union

from .ports import MCPPort

logger = logging.getLogger(__name__)


def parse_mcp_config(
    config: Union[str, Path, Dict[str, Any]],
) -> Dict[str, MCPPort]:
    """Parse an MCP server configuration and return adapter instances.

    Parameters
    ----------
    config : str | Path | dict
        Either a file path to a JSON config file, a JSON string, or an
        already-parsed dict.

    Returns
    -------
    dict[str, MCPPort]
        Mapping of server name → adapter instance (not yet connected).
    """
    raw = _load_config(config)
    servers = raw.get("mcpServers", raw)

    adapters: Dict[str, MCPPort] = {}
    for name, spec in servers.items():
        if not isinstance(spec, dict):
            logger.warning("Skipping non-dict server spec: %s", name)
            continue
        adapter = _build_adapter(name, spec)
        if adapter is not None:
            adapters[name] = adapter

    logger.info(
        "Parsed %d MCP server(s): %s",
        len(adapters),
        ", ".join(adapters.keys()),
    )
    return adapters


def _load_config(
    config: Union[str, Path, Dict[str, Any]],
) -> Dict[str, Any]:
    """Normalise config input to a dict."""
    if isinstance(config, dict):
        return config
    path = Path(str(config))
    if path.is_file():
        return json.loads(path.read_text(encoding="utf-8"))
    # Try as a JSON string.
    return json.loads(str(config))


def _build_adapter(name: str, spec: Dict[str, Any]) -> Any:
    """Build the appropriate adapter from a single server spec."""
    if "url" in spec:
        from .remote_adapter import MCPRemoteAdapter

        logger.info("  [%s] → MCPRemoteAdapter (url=%s)", name, spec["url"])
        return MCPRemoteAdapter(
            url=spec["url"],
            headers=spec.get("headers"),
            timeout=spec.get("timeout", 30),
        )

    if "command" in spec:
        from .local_adapter import MCPLocalAdapter

        logger.info(
            "  [%s] → MCPLocalAdapter (command=%s %s)",
            name,
            spec["command"],
            " ".join(spec.get("args", [])),
        )
        return MCPLocalAdapter(
            command=spec["command"],
            args=spec.get("args"),
            env=spec.get("env"),
            transport=spec.get("transport", "auto"),
            docker_image=spec.get("dockerImage"),
            docker_volumes=spec.get("dockerVolumes"),
            docker_network=spec.get("dockerNetwork"),
            working_dir=spec.get("workingDir"),
            startup_timeout=spec.get("startupTimeout", 30),
        )

    logger.warning(
        "  [%s] → Skipped (no 'url' or 'command' in spec)", name
    )
    return None
