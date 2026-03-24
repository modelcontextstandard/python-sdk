"""
title: MCS REST API Agent
description: Connects to any REST API via OpenAPI/Swagger spec. Discovers endpoints and lets the LLM call them as tools.
author: MCS
version: 1.0.0
requirements: mcs-driver-core>=0.2.2, mcs-driver-rest>=0.2, mcs-adapter-http>=0.2
"""

import json
import inspect
from pydantic import BaseModel, Field
from typing import Any

from mcs.driver.rest import RestDriver


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

    def __init__(self):
        self.valves = self.Valves()
        self.driver = None
        self._dynamically_generate_tools()

    def _ensure_driver(self):
        """Lazily build the REST driver on first tool call."""
        if self.driver:
            return

        tags = (
            [t.strip() for t in self.valves.include_tags.split(",") if t.strip()]
            if self.valves.include_tags
            else None
        )

        self.driver = RestDriver(
            url=self.valves.spec_url,
            include_tags=tags,
        )

    def _dynamically_generate_tools(self):
        """Discover tools from the OpenAPI spec and expose them to OpenWebUI."""
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
            print(f"MCS REST Init Error: {e}")

    def mcs_status(self) -> str:
        """Shows the status of the MCS REST Agent and available tools."""
        try:
            if not self.driver:
                self._ensure_driver()
            if not self.driver:
                return json.dumps({"status": "not ready"})
            tools = self.driver.list_tools()
            return json.dumps({
                "status": "active",
                "spec_url": self.valves.spec_url,
                "tools": [t.name for t in tools],
            }, indent=2)
        except Exception as e:
            return json.dumps({"status": "error", "message": str(e)})
