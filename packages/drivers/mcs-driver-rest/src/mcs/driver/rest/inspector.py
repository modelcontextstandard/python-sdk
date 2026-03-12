"""MCS REST Inspector -- interactive tool discovery for OpenAPI specs.

This module delegates to the generic ``mcs-inspector`` package when
available, falling back to a minimal built-in loop otherwise.

Run directly::

    python -m mcs.driver.rest.inspector https://reqres.in/openapi.json

Or preferably via the unified CLI::

    python -m mcs.inspector rest https://reqres.in/openapi.json
"""

from __future__ import annotations

import argparse
import sys

from mcs.driver.rest.tooldriver import RestToolDriver


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="mcs-rest-inspector",
        description=(
            "Inspect tools discovered from an OpenAPI spec.\n"
            "Tip: install mcs-inspector for the full interactive experience."
        ),
    )
    p.add_argument("url", help="OpenAPI specification URL")
    p.add_argument(
        "--include-tags", nargs="*", default=None,
        help="Only include operations whose tags match (case-insensitive)",
    )
    p.add_argument(
        "--include-paths", nargs="*", default=None,
        help="Only include these exact path strings",
    )
    p.add_argument("--bearer-token", default=None, help="Bearer token for authenticated APIs")
    return p.parse_args()


def main() -> None:
    args = _parse_args()

    kwargs = {}
    if args.bearer_token:
        kwargs["default_headers"] = {"Authorization": f"Bearer {args.bearer_token}"}

    td = RestToolDriver(
        args.url,
        include_tags=args.include_tags,
        include_paths=args.include_paths,
        **kwargs,
    )

    try:
        from mcs.inspector.core import ExtraColumn, run_inspector

        method_styles = {
            "GET": "green", "POST": "yellow",
            "PUT": "blue", "PATCH": "magenta", "DELETE": "red",
        }

        extra_columns = [
            ExtraColumn(
                header="Method",
                width=7,
                justify="center",
                value_fn=lambda tool, info: (
                    f"[{method_styles.get(info.get('method', ''), 'white')}]"
                    f"{info.get('method', '?')}"
                    f"[/{method_styles.get(info.get('method', ''), 'white')}]"
                ),
            ),
            ExtraColumn(
                header="Path",
                style="dim",
                value_fn=lambda tool, info: info.get("path", "?"),
            ),
        ]

        tools = td.list_tools()
        print(f"Parsed {len(tools)} tools (base: {td._base_url})\n")

        run_inspector(
            td,
            title="REST Inspector",
            extra_columns=extra_columns,
            driver_info=td._tool_map,
        )
    except ImportError:
        # Fallback: minimal output without rich / mcs-inspector
        tools = td.list_tools()
        print(f"Parsed {len(tools)} tools (base: {td._base_url})\n")
        for i, tool in enumerate(tools, 1):
            params = [p.name for p in tool.parameters]
            print(f"  {i:3d}. {tool.name:30s} params={params}")
        print(
            "\nInstall mcs-inspector for the full interactive experience:\n"
            "  pip install mcs-inspector[rest]"
        )


if __name__ == "__main__":
    main()
