"""Integration tests: real FastAPI servers + RestToolDriver end-to-end.

Tests:
  1. Single-server: all parameter types (path, query, header, cookie, body)
  2. Cross-server: combined spec with operations routed to different servers
"""

from __future__ import annotations

import json
import socket
import threading
import time
from typing import Any, Dict, Optional

import pytest
import uvicorn
from fastapi import Cookie, FastAPI, Header, Query
from pydantic import BaseModel

from mcs.adapter.http import HttpAdapter
from mcs.driver.rest import RestToolDriver


# ------------------------------------------------------------------ #
#  Helpers                                                            #
# ------------------------------------------------------------------ #

def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _start_server(app: FastAPI, port: int) -> threading.Thread:
    cfg = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(cfg)
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    _wait_for_port(port)
    return t


def _wait_for_port(port: int, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"Port {port} not ready within {timeout}s")


# ================================================================== #
#  App A -- "all-params" server                                        #
# ================================================================== #

app_a = FastAPI(title="AllParamsAPI", version="1.0.0")


class ItemCreate(BaseModel):
    name: str
    count: int = 1


@app_a.get("/items/{item_id}", operation_id="getItem")
def get_item(
    item_id: int,
    fields: Optional[str] = Query(None, description="Comma-separated field names"),
    x_request_id: Optional[str] = Header(None, alias="X-Request-Id"),
    session: Optional[str] = Cookie(None),
):
    return {
        "item_id": item_id,
        "fields": fields,
        "x_request_id": x_request_id,
        "session": session,
    }


@app_a.post("/items", operation_id="createItem")
def create_item(item: ItemCreate, dry_run: bool = Query(False, alias="dryRun")):
    return {"name": item.name, "count": item.count, "dry_run": dry_run}


@app_a.delete("/items/{item_id}", operation_id="deleteItem")
def delete_item(item_id: int):
    return {"deleted": item_id}


# ================================================================== #
#  App B -- "math" server (for cross-server test)                      #
# ================================================================== #

app_b = FastAPI(title="MathAPI", version="1.0.0")


@app_b.get("/add", operation_id="addNumbers")
def add_numbers(a: int = Query(...), b: int = Query(...)):
    return {"result": a + b}


@app_b.get("/multiply", operation_id="multiplyNumbers")
def multiply_numbers(a: int = Query(...), b: int = Query(...)):
    return {"result": a * b}


# ================================================================== #
#  App C -- "echo" server (for cross-server test)                      #
# ================================================================== #

app_c = FastAPI(title="EchoAPI", version="1.0.0")


@app_c.post("/echo", operation_id="echoPayload")
def echo_payload(payload: Dict[str, Any]):
    return {"echoed": payload}


# ================================================================== #
#  Fixtures                                                            #
# ================================================================== #

@pytest.fixture(scope="module")
def server_a():
    port = _free_port()
    _start_server(app_a, port)
    yield f"http://127.0.0.1:{port}"


@pytest.fixture(scope="module")
def server_b():
    port = _free_port()
    _start_server(app_b, port)
    yield f"http://127.0.0.1:{port}"


@pytest.fixture(scope="module")
def server_c():
    port = _free_port()
    _start_server(app_c, port)
    yield f"http://127.0.0.1:{port}"


# ================================================================== #
#  1. Single-server integration tests                                  #
# ================================================================== #

class TestSingleServer:
    """Full round-trip: fetch live OpenAPI spec -> parse -> execute."""

    def test_fetch_and_parse_spec(self, server_a: str):
        driver = RestToolDriver(f"{server_a}/openapi.json")
        tools = driver.list_tools()
        names = {t.name for t in tools}
        assert "getItem" in names
        assert "createItem" in names
        assert "deleteItem" in names

    def test_get_with_path_and_query(self, server_a: str):
        driver = RestToolDriver(f"{server_a}/openapi.json")
        result = json.loads(driver.execute_tool("getItem", {"item_id": 42, "fields": "name,count"}))
        assert result["item_id"] == 42
        assert result["fields"] == "name,count"

    def test_get_with_header_param(self, server_a: str):
        driver = RestToolDriver(f"{server_a}/openapi.json")
        result = json.loads(driver.execute_tool("getItem", {"item_id": 1, "X-Request-Id": "req-abc"}))
        assert result["x_request_id"] == "req-abc"

    def test_get_with_cookie_param(self, server_a: str):
        driver = RestToolDriver(f"{server_a}/openapi.json")
        result = json.loads(driver.execute_tool("getItem", {"item_id": 1, "session": "tok_xyz"}))
        assert result["session"] == "tok_xyz"

    def test_post_with_body_and_query(self, server_a: str):
        driver = RestToolDriver(f"{server_a}/openapi.json")
        result = json.loads(driver.execute_tool("createItem", {"name": "Widget", "count": 5, "dryRun": True}))
        assert result["name"] == "Widget"
        assert result["count"] == 5
        assert result["dry_run"] is True

    def test_delete(self, server_a: str):
        driver = RestToolDriver(f"{server_a}/openapi.json")
        result = json.loads(driver.execute_tool("deleteItem", {"item_id": 99}))
        assert result["deleted"] == 99

    def test_tool_parameters_have_correct_metadata(self, server_a: str):
        driver = RestToolDriver(f"{server_a}/openapi.json")
        tools = {t.name: t for t in driver.list_tools()}

        get_params = {p.name for p in tools["getItem"].parameters}
        assert "item_id" in get_params
        assert "fields" in get_params

        create_params = {p.name: p for p in tools["createItem"].parameters}
        assert "name" in create_params
        assert create_params["name"].required is True


# ================================================================== #
#  2. Cross-server integration tests                                   #
# ================================================================== #

class TestCrossServer:
    """Combined spec with per-operation servers pointing to different backends."""

    def _build_combined_spec(self, url_a: str, url_b: str, url_c: str) -> Dict[str, Any]:
        """Hand-craft a spec that routes operations to different servers."""
        return {
            "openapi": "3.0.0",
            "info": {"title": "Combined Toolset", "version": "1.0.0"},
            "servers": [{"url": url_a}],
            "paths": {
                "/items/{item_id}": {
                    "get": {
                        "operationId": "getItem",
                        "servers": [{"url": url_a}],
                        "parameters": [
                            {"name": "item_id", "in": "path", "required": True,
                             "schema": {"type": "integer"}}
                        ],
                        "responses": {"200": {"description": "ok"}}
                    }
                },
                "/add": {
                    "get": {
                        "operationId": "addNumbers",
                        "servers": [{"url": url_b}],
                        "parameters": [
                            {"name": "a", "in": "query", "required": True, "schema": {"type": "integer"}},
                            {"name": "b", "in": "query", "required": True, "schema": {"type": "integer"}},
                        ],
                        "responses": {"200": {"description": "ok"}}
                    }
                },
                "/multiply": {
                    "get": {
                        "operationId": "multiplyNumbers",
                        "servers": [{"url": url_b}],
                        "parameters": [
                            {"name": "a", "in": "query", "required": True, "schema": {"type": "integer"}},
                            {"name": "b", "in": "query", "required": True, "schema": {"type": "integer"}},
                        ],
                        "responses": {"200": {"description": "ok"}}
                    }
                },
                "/echo": {
                    "post": {
                        "operationId": "echoPayload",
                        "servers": [{"url": url_c}],
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "message": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        },
                        "responses": {"200": {"description": "ok"}}
                    }
                }
            }
        }

    def _make_driver_from_spec(self, spec: Dict[str, Any]) -> RestToolDriver:
        driver = RestToolDriver.__new__(RestToolDriver)
        driver.spec_url = "synthetic://combined"
        driver._http = HttpAdapter()
        driver._tools = None
        driver._tool_map = {}
        driver._base_url = spec["servers"][0]["url"]
        driver._parse_spec(spec)
        return driver

    def test_combined_spec_parses_all_tools(self, server_a, server_b, server_c):
        spec = self._build_combined_spec(server_a, server_b, server_c)
        driver = self._make_driver_from_spec(spec)
        names = {t.name for t in driver.list_tools()}
        assert names == {"getItem", "addNumbers", "multiplyNumbers", "echoPayload"}

    def test_routes_to_correct_server_a(self, server_a, server_b, server_c):
        spec = self._build_combined_spec(server_a, server_b, server_c)
        driver = self._make_driver_from_spec(spec)
        result = json.loads(driver.execute_tool("getItem", {"item_id": 7}))
        assert result["item_id"] == 7

    def test_routes_to_correct_server_b_add(self, server_a, server_b, server_c):
        spec = self._build_combined_spec(server_a, server_b, server_c)
        driver = self._make_driver_from_spec(spec)
        result = json.loads(driver.execute_tool("addNumbers", {"a": 3, "b": 5}))
        assert result["result"] == 8

    def test_routes_to_correct_server_b_multiply(self, server_a, server_b, server_c):
        spec = self._build_combined_spec(server_a, server_b, server_c)
        driver = self._make_driver_from_spec(spec)
        result = json.loads(driver.execute_tool("multiplyNumbers", {"a": 4, "b": 6}))
        assert result["result"] == 24

    def test_routes_to_correct_server_c_echo(self, server_a, server_b, server_c):
        spec = self._build_combined_spec(server_a, server_b, server_c)
        driver = self._make_driver_from_spec(spec)
        result = json.loads(driver.execute_tool("echoPayload", {"message": "hello MCS"}))
        assert result["echoed"]["message"] == "hello MCS"

    def test_wrong_server_would_fail(self, server_a, server_b, server_c):
        """Verify that the routing actually matters -- calling math on the items server fails."""
        spec = self._build_combined_spec(server_a, server_b, server_c)
        spec["paths"]["/add"]["get"]["servers"] = [{"url": server_a}]
        driver = self._make_driver_from_spec(spec)
        with pytest.raises(Exception):
            driver.execute_tool("addNumbers", {"a": 1, "b": 2})
