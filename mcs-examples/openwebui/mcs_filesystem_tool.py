"""
title: MCS Filesystem Agent
description: Local file access via MCS. Lists directories, reads and writes files on the server.
author: MCS
version: 1.0.0
requirements: mcs-driver-core>=0.2.2, mcs-driver-filesystem>=0.2, mcs-adapter-localfs>=0.1
"""

import json
import inspect
from pydantic import BaseModel, Field
from typing import Any

from mcs.driver.filesystem import FilesystemDriver


class Tools:
    class Valves(BaseModel):
        root_path: str = Field(
            default=".",
            description="Root directory the agent is allowed to access",
        )
        adapter: str = Field(
            default="localfs",
            description="Filesystem adapter: 'localfs' or 'smb'",
        )

    def __init__(self):
        self.valves = self.Valves()
        self.driver = None
        self._dynamically_generate_tools()

    def _ensure_driver(self):
        """Lazily build the filesystem driver on first tool call."""
        if self.driver:
            return

        self.driver = FilesystemDriver(
            adapter=self.valves.adapter,
            base_dir=self.valves.root_path,
        )

    def _dynamically_generate_tools(self):
        """Discover tools from the driver and expose them to OpenWebUI."""
        try:
            self._ensure_driver()
            if not self.driver:
                return
            mcs_tools = self.driver.list_tools()

            for tool in mcs_tools:

                def make_caller(tool_name=tool.name):
                    def dynamic_func(self, **kwargs) -> str:
                        self._ensure_driver()
                        if not self.driver:
                            return json.dumps({"error": "Driver not ready."})

                        actual_params = {}
                        if "kwargs" in kwargs and isinstance(kwargs["kwargs"], str):
                            try:
                                actual_params = json.loads(kwargs["kwargs"])
                            except json.JSONDecodeError:
                                actual_params = kwargs
                        elif "kwargs" in kwargs and isinstance(kwargs["kwargs"], dict):
                            actual_params = kwargs["kwargs"]
                        else:
                            actual_params = kwargs

                        try:
                            result = self.driver.execute_tool(tool_name, actual_params)
                            if isinstance(result, (dict, list)):
                                return json.dumps(result, ensure_ascii=False)
                            return str(result)
                        except Exception as e:
                            return f"Error: {str(e)}"

                    return dynamic_func

                func = make_caller()

                func.__name__ = tool.name
                func.__doc__ = (
                    tool.description or tool.title or "No description provided."
                )

                sig_params = [
                    inspect.Parameter("self", inspect.Parameter.POSITIONAL_OR_KEYWORD)
                ]
                annotations = {}

                for param in tool.parameters:
                    sig_params.append(
                        inspect.Parameter(
                            name=param.name,
                            kind=inspect.Parameter.POSITIONAL_OR_KEYWORD,
                            annotation=str,
                            default=inspect.Parameter.empty if param.required else None,
                        )
                    )
                    annotations[param.name] = str

                annotations["return"] = str
                func.__annotations__ = annotations
                func.__signature__ = inspect.Signature(sig_params)  # type: ignore[attr-defined]

                setattr(self, tool.name, func.__get__(self))

        except Exception as e:
            print(f"MCS Filesystem Init Error: {e}")

    def mcs_status(self) -> str:
        """Shows the status of the MCS Filesystem Agent and available tools."""
        try:
            if not self.driver:
                self._ensure_driver()
            if not self.driver:
                return json.dumps({"status": "not ready"})
            tools = self.driver.list_tools()
            return json.dumps({
                "status": "active",
                "root_path": self.valves.root_path,
                "tools": [t.name for t in tools],
            }, indent=2)
        except Exception as e:
            return json.dumps({"status": "error", "message": str(e)})
