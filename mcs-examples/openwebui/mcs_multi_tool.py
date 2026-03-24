"""
title: MCS Multi-Driver Agent
description: Combines REST API and filesystem access in a single tool. Uses the MCS Orchestrator with NamespacingLayer to avoid tool name collisions across drivers.
author: MCS
version: 1.0.0
requirements: mcs-driver-core>=0.2.2, mcs-driver-rest>=0.2, mcs-driver-filesystem>=0.2, mcs-adapter-http>=0.2, mcs-adapter-localfs>=0.1, mcs-orchestrator-base>=0.1
"""

import json
import inspect
from pydantic import BaseModel, Field
from typing import Any

from mcs.driver.rest import RestDriver
from mcs.driver.filesystem import FilesystemDriver
from mcs.orchestrator.base import BaseOrchestrator, ToolPipeline, NamespacingLayer


class Tools:
    class Valves(BaseModel):
        spec_url: str = Field(
            default="https://mcsd.io/context7.json",
            description="URL to an OpenAPI or Swagger 2.0 spec (JSON or YAML)",
        )
        include_tags: str = Field(
            default="",
            description="Comma-separated OpenAPI tags to include (empty = all)",
        )
        root_path: str = Field(
            default=".",
            description="Root directory the filesystem agent is allowed to access",
        )

    def __init__(self):
        self.valves = self.Valves()
        self.orchestrator = None
        self._dynamically_generate_tools()

    def _ensure_orchestrator(self):
        """Lazily build the orchestrator with both drivers on first tool call."""
        if self.orchestrator:
            return

        tags = (
            [t.strip() for t in self.valves.include_tags.split(",") if t.strip()]
            if self.valves.include_tags
            else None
        )

        rest_driver = RestDriver(url=self.valves.spec_url, include_tags=tags)
        fs_driver = FilesystemDriver(adapter="localfs", root=self.valves.root_path)

        self.orchestrator = BaseOrchestrator(
            resolution_strategy=ToolPipeline(layers=[NamespacingLayer()]),
        )
        self.orchestrator.add_driver(rest_driver, label="api")
        self.orchestrator.add_driver(fs_driver, label="files")

    def _dynamically_generate_tools(self):
        """Discover tools from all drivers and expose them to OpenWebUI.

        The NamespacingLayer automatically prefixes tool names when multiple
        drivers are registered (e.g. ``api__search_repos``, ``files__read_file``),
        preventing collisions when different drivers expose tools with the
        same name.
        """
        try:
            self._ensure_orchestrator()
            if not self.orchestrator:
                return
            mcs_tools = self.orchestrator.list_tools()

            for tool in mcs_tools:

                def make_caller(tool_name=tool.name):
                    def dynamic_func(self, **kwargs) -> str:
                        self._ensure_orchestrator()
                        if not self.orchestrator:
                            return json.dumps({"error": "Orchestrator not ready."})

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
                            result = self.orchestrator.execute_tool(tool_name, actual_params)
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
            print(f"MCS Multi-Driver Init Error: {e}")

    def mcs_status(self) -> str:
        """Shows the status of the MCS Multi-Driver Agent, registered drivers, and all available tools."""
        try:
            if not self.orchestrator:
                self._ensure_orchestrator()
            if not self.orchestrator:
                return json.dumps({"status": "not ready"})
            tools = self.orchestrator.list_tools()
            return json.dumps({
                "status": "active",
                "drivers": self.orchestrator.labels,
                "tools": [t.name for t in tools],
            }, indent=2)
        except Exception as e:
            return json.dumps({"status": "error", "message": str(e)})
