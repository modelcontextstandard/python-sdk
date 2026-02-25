"""Tests for RestDriver -- the hybrid LLM-facing wrapper around MCSToolDriver."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

import pytest

from dataclasses import dataclass
from mcs.driver.core import (
    MCSToolDriver,
    Tool,
    ToolParameter,
    DriverMeta,
    DriverBinding,
    DriverResponse,
)
from mcs.driver.core.mixins import SupportsHealthcheck, HealthCheckResult, HealthStatus
from mcs.driver.rest import RestDriver


# ------------------------------------------------------------------ #
#  Fake ToolDriver for isolation                                      #
# ------------------------------------------------------------------ #

@dataclass(frozen=True)
class _FakeToolMeta(DriverMeta):
    id: str = "fake-id"
    name: str = "Fake"
    version: str = "0.0.1"
    bindings: tuple[DriverBinding, ...] = ()
    supported_llms: None = None
    capabilities: tuple[str, ...] = ()


class FakeToolDriver(MCSToolDriver, SupportsHealthcheck):
    meta = _FakeToolMeta()

    def __init__(self, tools: list[Tool] | None = None):
        self._tools = tools or [
            Tool(
                name="addNumbers",
                description="Add two numbers",
                parameters=[
                    ToolParameter(name="a", description="first", required=True, schema={"type": "integer"}),
                    ToolParameter(name="b", description="second", required=True, schema={"type": "integer"}),
                ],
            ),
            Tool(
                name="greet",
                description="Return a greeting",
                parameters=[
                    ToolParameter(name="name", description="who to greet", required=True, schema={"type": "string"}),
                ],
            ),
        ]
        self._execute_results: dict[str, Any] = {
            "addNumbers": '{"result": 8}',
            "greet": '{"message": "Hello, World!"}',
        }

    def list_tools(self) -> list[Tool]:
        return self._tools

    def execute_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        if tool_name not in self._execute_results:
            raise ValueError(f"Unknown tool: {tool_name}")
        return self._execute_results[tool_name]

    def healthcheck(self) -> HealthCheckResult:
        return {"status": HealthStatus.OK}


# ================================================================== #
#  1. Delegation                                                       #
# ================================================================== #

class TestDelegation:

    def test_list_tools_delegates(self):
        fake = FakeToolDriver()
        driver = RestDriver(_tooldriver=fake)
        tools = driver.list_tools()
        assert len(tools) == 2
        assert {t.name for t in tools} == {"addNumbers", "greet"}

    def test_execute_tool_delegates(self):
        fake = FakeToolDriver()
        driver = RestDriver(_tooldriver=fake)
        result = driver.execute_tool("addNumbers", {"a": 3, "b": 5})
        assert result == '{"result": 8}'

    def test_healthcheck_delegates(self):
        fake = FakeToolDriver()
        driver = RestDriver(_tooldriver=fake)
        result = driver.healthcheck()
        assert result["status"] == HealthStatus.OK

    def test_healthcheck_unknown_when_not_supported(self):
        td = MagicMock(spec=MCSToolDriver)
        td.list_tools.return_value = []
        driver = RestDriver(_tooldriver=td)
        result = driver.healthcheck()
        assert result["status"] == HealthStatus.UNKNOWN


# ================================================================== #
#  2. get_function_description                                         #
# ================================================================== #

class TestGetFunctionDescription:

    def test_builds_json_schema(self):
        driver = RestDriver(_tooldriver=FakeToolDriver())
        desc = driver.get_function_description()
        schema = json.loads(desc)
        assert "tools" in schema
        names = {t["name"] for t in schema["tools"]}
        assert names == {"addNumbers", "greet"}

    def test_schema_contains_parameters(self):
        driver = RestDriver(_tooldriver=FakeToolDriver())
        schema = json.loads(driver.get_function_description())
        add_tool = next(t for t in schema["tools"] if t["name"] == "addNumbers")
        props = add_tool["parameters"]["properties"]
        assert "a" in props
        assert "b" in props
        assert add_tool["parameters"]["required"] == ["a", "b"]

    def test_custom_description_overrides(self):
        driver = RestDriver(_tooldriver=FakeToolDriver(), custom_tool_description="custom tools here")
        assert driver.get_function_description() == "custom tools here"


# ================================================================== #
#  3. get_driver_system_message                                        #
# ================================================================== #

class TestGetDriverSystemMessage:

    def test_contains_tools(self):
        driver = RestDriver(_tooldriver=FakeToolDriver())
        msg = driver.get_driver_system_message()
        assert "addNumbers" in msg
        assert "greet" in msg
        assert '"tool"' in msg

    def test_custom_system_message_overrides(self):
        driver = RestDriver(_tooldriver=FakeToolDriver(), custom_driver_system_message="Custom system")
        assert driver.get_driver_system_message() == "Custom system"


# ================================================================== #
#  4. process_llm_response                                             #
# ================================================================== #

class TestProcessLlmResponse:

    def test_no_json_returns_empty(self):
        driver = RestDriver(_tooldriver=FakeToolDriver())
        resp = driver.process_llm_response("Just a plain text answer.")
        assert not resp.call_executed
        assert not resp.call_failed
        assert resp.messages is None

    def test_valid_tool_call(self):
        driver = RestDriver(_tooldriver=FakeToolDriver())
        llm_output = json.dumps({"tool": "addNumbers", "arguments": {"a": 3, "b": 5}})
        resp = driver.process_llm_response(llm_output)
        assert resp.call_executed is True
        assert resp.tool_call_result == '{"result": 8}'
        assert resp.messages is not None

    def test_tool_call_in_markdown_fence(self):
        driver = RestDriver(_tooldriver=FakeToolDriver())
        llm_output = '```json\n{"tool": "greet", "arguments": {"name": "Alice"}}\n```'
        resp = driver.process_llm_response(llm_output)
        assert resp.call_executed is True
        assert "Hello" in resp.tool_call_result

    def test_unknown_tool_passthrough(self):
        driver = RestDriver(_tooldriver=FakeToolDriver())
        llm_output = json.dumps({"tool": "unknownTool", "arguments": {}})
        resp = driver.process_llm_response(llm_output)
        assert not resp.call_executed
        assert not resp.call_failed
        assert resp.messages is None

    def test_missing_tool_field_returns_empty(self):
        """JSON without a tool field is treated as 'no tool call'."""
        driver = RestDriver(_tooldriver=FakeToolDriver())
        llm_output = json.dumps({"arguments": {"a": 1}})
        resp = driver.process_llm_response(llm_output)
        assert resp.call_executed is False
        assert resp.call_failed is False

    def test_invalid_json_returns_empty(self):
        """Unparseable JSON is treated as 'no tool call'."""
        driver = RestDriver(_tooldriver=FakeToolDriver())
        llm_output = '{"tool": "addNumbers", broken json}'
        resp = driver.process_llm_response(llm_output)
        assert resp.call_executed is False
        assert resp.call_failed is False

    def test_execution_error_fails(self):
        fake = FakeToolDriver()
        fake._execute_results["addNumbers"] = None
        driver = RestDriver(_tooldriver=fake)

        def boom(name, args):
            raise RuntimeError("DB connection lost")
        fake.execute_tool = boom

        llm_output = json.dumps({"tool": "addNumbers", "arguments": {"a": 1, "b": 2}})
        resp = driver.process_llm_response(llm_output)
        assert resp.call_failed is True
        assert "DB connection lost" in resp.call_detail

    def test_dict_llm_response_handled(self):
        driver = RestDriver(_tooldriver=FakeToolDriver())
        resp = driver.process_llm_response({"tool": "greet", "arguments": {"name": "Bob"}})
        assert resp.call_executed is True

    def test_name_field_also_accepted(self):
        driver = RestDriver(_tooldriver=FakeToolDriver())
        llm_output = json.dumps({"name": "addNumbers", "arguments": {"a": 1, "b": 2}})
        resp = driver.process_llm_response(llm_output)
        assert resp.call_executed is True


# ================================================================== #
#  5. DriverMeta                                                       #
# ================================================================== #

class TestRestDriverMeta:

    def test_meta_attributes(self):
        driver = RestDriver(_tooldriver=FakeToolDriver())
        assert driver.meta.name == "REST MCS Driver"
        assert "standalone" in driver.meta.capabilities
        assert "orchestratable" in driver.meta.capabilities
        assert "healthcheck" in driver.meta.capabilities
        assert driver.meta.supported_llms == ("*",)
