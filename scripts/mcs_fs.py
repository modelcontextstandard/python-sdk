#!/usr/bin/env python3
"""
MCS Filesystem – Skill Script
===============================

Thin wrapper around FilesystemDriver.
The tools come from the driver. This script just calls them.

Usage:
    python mcs_fs.py status
    python mcs_fs.py list <path>
    python mcs_fs.py read <path>
    python mcs_fs.py write <path> --stdin
    python mcs_fs.py exec <tool_name> '{"param": "value"}'
"""

import argparse
import json
import os
import sys

try:
    from mcs.driver.filesystem import FilesystemDriver
except ImportError:
    print(json.dumps({
        "error": "MCS Filesystem Driver not installed",
        "fix": "pip install mcs-driver-core>=0.2.2 mcs-driver-filesystem>=0.2 mcs-adapter-localfs>=0.1",
    }))
    sys.exit(1)


def get_driver(base_dir: str = ".") -> FilesystemDriver:
    return FilesystemDriver(adapter="localfs", base_dir=base_dir)


def cmd_status(driver):
    tools = driver.list_tools()
    print(json.dumps({
        "driver": driver.meta.name,
        "version": driver.meta.version,
        "tools": [
            {
                "name": t.name,
                "description": t.description,
                "parameters": [
                    {"name": p.name, "required": p.required, "description": p.description}
                    for p in t.parameters
                ],
            }
            for t in tools
        ],
    }, indent=2, ensure_ascii=False))


def cmd_exec(driver, tool_name: str, params_json: str):
    try:
        params = json.loads(params_json) if params_json else {}
    except json.JSONDecodeError as e:
        print(json.dumps({"error": f"Invalid JSON: {e}"}))
        sys.exit(1)

    result = driver.execute_tool(tool_name, params)
    if isinstance(result, (dict, list)):
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(result)


def main():
    parser = argparse.ArgumentParser(description="MCS Filesystem Skill")
    parser.add_argument("--base-dir", default=".", help="Root directory for the driver")
    parser.add_argument("command", choices=["status", "list", "read", "write", "exec"])
    parser.add_argument("args", nargs="*")

    args = parser.parse_args()
    driver = get_driver(args.base_dir)

    if args.command == "status":
        cmd_status(driver)

    elif args.command == "list":
        path = args.args[0] if args.args else "."
        cmd_exec(driver, "list_directory", json.dumps({"path": path}))

    elif args.command == "read":
        if not args.args:
            print("Usage: mcs_fs.py read <path>", file=sys.stderr)
            sys.exit(1)
        cmd_exec(driver, "read_file", json.dumps({"path": args.args[0]}))

    elif args.command == "write":
        if not args.args:
            print("Usage: mcs_fs.py write <path> [content | --stdin]", file=sys.stderr)
            sys.exit(1)
        filepath = args.args[0]
        if len(args.args) > 1 and args.args[1] == "--stdin":
            content = sys.stdin.read()
        elif len(args.args) > 1:
            content = " ".join(args.args[1:])
        else:
            content = sys.stdin.read()
        cmd_exec(driver, "write_file", json.dumps({"path": filepath, "content": content}))

    elif args.command == "exec":
        if not args.args:
            print("Usage: mcs_fs.py exec <tool_name> ['{json}']", file=sys.stderr)
            sys.exit(1)
        tool_name = args.args[0]
        params = args.args[1] if len(args.args) > 1 else "{}"
        cmd_exec(driver, tool_name, params)


if __name__ == "__main__":
    main()
