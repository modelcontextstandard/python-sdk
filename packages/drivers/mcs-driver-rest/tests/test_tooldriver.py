"""Tests for RestToolDriver -- parsing, conversion, ref-resolution, execution."""

from __future__ import annotations

import json
import pathlib
from typing import Any, Dict
from unittest.mock import patch

import pytest

from mcs.adapter.http import HttpAdapter
from mcs.driver.rest import RestToolDriver


# ------------------------------------------------------------------ #
#  Helpers                                                            #
# ------------------------------------------------------------------ #

def _make_driver(
    spec_dict: Dict[str, Any],
    base_url: str = "https://api.example.com",
) -> RestToolDriver:
    """Create a driver with a pre-loaded spec (bypass HTTP fetch)."""
    driver = RestToolDriver.__new__(RestToolDriver)
    driver.spec_url = "https://example.com/spec.json"
    driver._http = HttpAdapter()
    driver._tools = None
    driver._tool_map = {}
    driver._base_url = base_url

    if spec_dict.get("swagger", "").startswith("2"):
        spec_dict = driver._convert_swagger2(spec_dict)

    driver._parse_spec(spec_dict)
    return driver


def _load_file(path: pathlib.Path) -> Dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix in (".yaml", ".yml"):
        import yaml
        return yaml.safe_load(text)
    return json.loads(text)


# ================================================================== #
#  1. Parsing -- every fixture must parse without error                #
# ================================================================== #

class TestParseAllFixtures:
    """Every downloaded fixture must parse into at least one tool."""

    def test_fixture_parses_without_error(self, spec_file: pathlib.Path, load_spec):
        spec = load_spec(spec_file)
        driver = _make_driver(spec)
        tools = driver.list_tools()
        assert isinstance(tools, list)
        assert len(tools) > 0, f"{spec_file.name} produced no tools"

    def test_every_tool_has_name_and_description(self, spec_file: pathlib.Path, load_spec):
        spec = load_spec(spec_file)
        driver = _make_driver(spec)
        for tool in driver.list_tools():
            assert tool.name, "Tool name must not be empty"
            assert tool.description, "Tool description must not be empty"


# ================================================================== #
#  2. Swagger 2.0 conversion                                          #
# ================================================================== #

class TestSwagger2Conversion:

    def test_swagger2_converted_to_openapi3_shape(self, swagger2_file: pathlib.Path, load_spec):
        raw = load_spec(swagger2_file)
        assert raw.get("swagger", "").startswith("2"), f"{swagger2_file.name} is not Swagger 2.0"
        converted = RestToolDriver._convert_swagger2(raw)
        assert "openapi" in converted
        assert "servers" in converted
        assert len(converted["servers"]) > 0
        assert "paths" in converted

    def test_swagger2_definitions_become_components_schemas(self, swagger2_file: pathlib.Path, load_spec):
        raw = load_spec(swagger2_file)
        if "definitions" not in raw:
            pytest.skip("No definitions in this spec")
        converted = RestToolDriver._convert_swagger2(raw)
        assert "components" in converted
        assert "schemas" in converted["components"]
        assert len(converted["components"]["schemas"]) == len(raw["definitions"])

    def test_swagger2_ref_paths_rewritten(self, swagger2_file: pathlib.Path, load_spec):
        raw = load_spec(swagger2_file)
        if "definitions" not in raw:
            pytest.skip("No definitions to rewrite")
        converted = RestToolDriver._convert_swagger2(raw)
        text = json.dumps(converted)
        assert "#/definitions/" not in text, "Old #/definitions/ refs should be rewritten"

    def test_swagger2_body_param_becomes_request_body(self):
        spec = {
            "swagger": "2.0",
            "info": {"title": "Test", "version": "1.0"},
            "host": "api.example.com",
            "basePath": "/v1",
            "schemes": ["https"],
            "paths": {
                "/items": {
                    "post": {
                        "operationId": "createItem",
                        "parameters": [
                            {"in": "body", "name": "body", "required": True,
                             "schema": {"type": "object", "properties": {"name": {"type": "string"}}}}
                        ],
                        "responses": {"200": {"description": "ok"}}
                    }
                }
            }
        }
        converted = RestToolDriver._convert_swagger2(spec)
        post_op = converted["paths"]["/items"]["post"]
        assert "requestBody" in post_op
        assert "content" in post_op["requestBody"]
        assert "application/json" in post_op["requestBody"]["content"]

    def test_swagger2_base_url_construction(self):
        spec = {
            "swagger": "2.0",
            "info": {"title": "Test", "version": "1.0"},
            "host": "api.example.com",
            "basePath": "/v2",
            "schemes": ["https", "http"],
            "paths": {}
        }
        converted = RestToolDriver._convert_swagger2(spec)
        assert converted["servers"][0]["url"] == "https://api.example.com/v2"


# ================================================================== #
#  3. $ref resolution                                                  #
# ================================================================== #

class TestRefResolution:

    def test_simple_ref(self):
        spec = {
            "components": {"schemas": {"Pet": {"type": "object", "properties": {"name": {"type": "string"}}}}},
            "paths": {}
        }
        driver = RestToolDriver.__new__(RestToolDriver)
        obj = {"$ref": "#/components/schemas/Pet"}
        resolved = driver._resolve_ref(obj, spec)
        assert resolved["type"] == "object"
        assert "name" in resolved["properties"]

    def test_nested_ref(self):
        spec = {
            "components": {
                "schemas": {
                    "Pet": {"type": "object", "properties": {"category": {"$ref": "#/components/schemas/Category"}}},
                    "Category": {"type": "object", "properties": {"id": {"type": "integer"}}}
                }
            }
        }
        driver = RestToolDriver.__new__(RestToolDriver)
        resolved = driver._resolve_ref({"$ref": "#/components/schemas/Pet"}, spec)
        assert resolved["properties"]["category"]["type"] == "object"

    def test_ref_in_array(self):
        spec = {
            "components": {"schemas": {"Tag": {"type": "object", "properties": {"name": {"type": "string"}}}}}
        }
        driver = RestToolDriver.__new__(RestToolDriver)
        arr = [{"$ref": "#/components/schemas/Tag"}, {"type": "string"}]
        resolved = driver._resolve_ref(arr, spec)
        assert resolved[0]["type"] == "object"
        assert resolved[1]["type"] == "string"

    def test_nonlocal_ref_unchanged(self):
        driver = RestToolDriver.__new__(RestToolDriver)
        obj = {"$ref": "https://example.com/other.json#/Foo"}
        resolved = driver._resolve_ref(obj, {})
        assert resolved == obj

    def test_petstore3_refs_resolve(self, load_spec):
        from conftest import OPENAPI3_DIR
        path = OPENAPI3_DIR / "petstore3-live.json"
        if not path.exists():
            pytest.skip("petstore3-live.json not available")
        spec = load_spec(path)
        driver = _make_driver(spec)
        tools = driver.list_tools()
        assert len(tools) > 10


# ================================================================== #
#  4. Path-level parameter inheritance                                 #
# ================================================================== #

class TestPathLevelParams:

    def test_path_params_inherited(self):
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "Test", "version": "1.0"},
            "servers": [{"url": "https://api.example.com"}],
            "paths": {
                "/items/{itemId}": {
                    "parameters": [
                        {"name": "itemId", "in": "path", "required": True, "schema": {"type": "integer"}}
                    ],
                    "get": {
                        "operationId": "getItem",
                        "responses": {"200": {"description": "ok"}}
                    },
                    "delete": {
                        "operationId": "deleteItem",
                        "responses": {"200": {"description": "ok"}}
                    }
                }
            }
        }
        driver = _make_driver(spec)
        tools = {t.name: t for t in driver.list_tools()}
        assert "getItem" in tools
        assert "deleteItem" in tools
        assert any(p.name == "itemId" for p in tools["getItem"].parameters)
        assert any(p.name == "itemId" for p in tools["deleteItem"].parameters)

    def test_operation_param_overrides_path_param(self):
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "Test", "version": "1.0"},
            "servers": [{"url": "https://api.example.com"}],
            "paths": {
                "/items/{itemId}": {
                    "parameters": [
                        {"name": "itemId", "in": "path", "required": True,
                         "description": "path-level", "schema": {"type": "integer"}}
                    ],
                    "get": {
                        "operationId": "getItem",
                        "parameters": [
                            {"name": "itemId", "in": "path", "required": True,
                             "description": "op-level", "schema": {"type": "string"}}
                        ],
                        "responses": {"200": {"description": "ok"}}
                    }
                }
            }
        }
        driver = _make_driver(spec)
        tools = {t.name: t for t in driver.list_tools()}
        item_id_params = [p for p in tools["getItem"].parameters if p.name == "itemId"]
        assert len(item_id_params) == 1, "Should not duplicate param"
        assert item_id_params[0].description == "op-level"


# ================================================================== #
#  5. operationId fallback generation                                  #
# ================================================================== #

class TestOperationIdFallback:

    def test_missing_operation_id_generates_name(self):
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "Test", "version": "1.0"},
            "servers": [{"url": "https://api.example.com"}],
            "paths": {
                "/users/{userId}/orders": {
                    "get": {
                        "summary": "List user orders",
                        "responses": {"200": {"description": "ok"}}
                    }
                }
            }
        }
        driver = _make_driver(spec)
        tools = driver.list_tools()
        assert len(tools) == 1
        assert tools[0].name == "get_users_userId_orders"

    def test_generate_operation_id_format(self):
        assert RestToolDriver._generate_operation_id("GET", "/pets/{petId}") == "get_pets_petId"
        assert RestToolDriver._generate_operation_id("POST", "/users") == "post_users"
        assert RestToolDriver._generate_operation_id("DELETE", "/a/{b}/c/{d}") == "delete_a_b_c_d"


# ================================================================== #
#  6. YAML parsing                                                     #
# ================================================================== #

class TestYamlParsing:

    def test_yaml_fixtures_parse(self, load_spec):
        from conftest import ALL_FIXTURES
        yaml_files = [f for f in ALL_FIXTURES if f.suffix in (".yaml", ".yml")]
        assert len(yaml_files) > 0, "Need at least one YAML fixture"
        for path in yaml_files:
            spec = load_spec(path)
            driver = _make_driver(spec)
            tools = driver.list_tools()
            assert len(tools) > 0, f"{path.name} produced no tools"

    def test_parse_raw_spec_yaml(self):
        yaml_text = """
openapi: "3.0.0"
info:
  title: Mini
  version: "1.0"
paths:
  /ping:
    get:
      operationId: ping
      responses:
        "200":
          description: pong
"""
        spec = RestToolDriver._parse_raw_spec(yaml_text)
        assert spec["openapi"] == "3.0.0"
        assert "/ping" in spec["paths"]

    def test_parse_raw_spec_invalid_json_without_yaml_raises(self):
        import mcs.driver.rest.tooldriver as mod
        orig = mod._HAS_YAML
        mod._HAS_YAML = False
        try:
            with pytest.raises(ValueError, match="pyyaml"):
                RestToolDriver._parse_raw_spec("not: valid: json{{{")
        finally:
            mod._HAS_YAML = orig


# ================================================================== #
#  7. execute_tool -- parameter routing                                #
# ================================================================== #

class TestExecuteTool:

    @pytest.fixture()
    def petstore_driver(self) -> RestToolDriver:
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "Test", "version": "1.0"},
            "servers": [{"url": "https://api.example.com"}],
            "paths": {
                "/pets/{petId}": {
                    "get": {
                        "operationId": "getPet",
                        "parameters": [
                            {"name": "petId", "in": "path", "required": True, "schema": {"type": "integer"}},
                            {"name": "fields", "in": "query", "schema": {"type": "string"}},
                            {"name": "X-Request-Id", "in": "header", "schema": {"type": "string"}},
                            {"name": "session", "in": "cookie", "schema": {"type": "string"}},
                        ],
                        "responses": {"200": {"description": "ok"}}
                    }
                },
                "/pets": {
                    "post": {
                        "operationId": "createPet",
                        "parameters": [
                            {"name": "dryRun", "in": "query", "schema": {"type": "boolean"}}
                        ],
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "name": {"type": "string"},
                                            "tag": {"type": "string"}
                                        },
                                        "required": ["name"]
                                    }
                                }
                            }
                        },
                        "responses": {"201": {"description": "created"}}
                    }
                }
            }
        }
        return _make_driver(spec)

    def test_get_path_and_query_params(self, petstore_driver: RestToolDriver):
        with patch.object(petstore_driver._http, "request", return_value='{"id":1}') as mock:
            petstore_driver.execute_tool("getPet", {"petId": 42, "fields": "name,tag"})
            mock.assert_called_once()
            _, url = mock.call_args.args
            assert "/pets/42" in url
            assert mock.call_args.kwargs["params"] == {"fields": "name,tag"}

    def test_get_header_params_passed(self, petstore_driver: RestToolDriver):
        with patch.object(petstore_driver._http, "request", return_value='{}') as mock:
            petstore_driver.execute_tool("getPet", {"petId": 1, "X-Request-Id": "abc-123"})
            headers = mock.call_args.kwargs.get("headers")
            assert headers is not None
            assert headers["X-Request-Id"] == "abc-123"

    def test_get_cookie_params_as_header(self, petstore_driver: RestToolDriver):
        with patch.object(petstore_driver._http, "request", return_value='{}') as mock:
            petstore_driver.execute_tool("getPet", {"petId": 1, "session": "tok_abc"})
            headers = mock.call_args.kwargs.get("headers")
            assert headers is not None
            assert "Cookie" in headers
            assert "session=tok_abc" in headers["Cookie"]

    def test_post_body_and_query_separated(self, petstore_driver: RestToolDriver):
        with patch.object(petstore_driver._http, "request", return_value='{"id":1}') as mock:
            petstore_driver.execute_tool("createPet", {"name": "Fido", "tag": "dog", "dryRun": True})
            mock.assert_called_once()
            assert mock.call_args.kwargs["params"] == {"dryRun": True}
            assert mock.call_args.kwargs["json_body"] == {"name": "Fido", "tag": "dog"}

    def test_post_empty_query_not_sent(self, petstore_driver: RestToolDriver):
        with patch.object(petstore_driver._http, "request", return_value='{}') as mock:
            petstore_driver.execute_tool("createPet", {"name": "Fido"})
            assert mock.call_args.kwargs["params"] == {}

    def test_unknown_tool_raises(self, petstore_driver: RestToolDriver):
        with pytest.raises(ValueError, match="not found"):
            petstore_driver.execute_tool("nonExistent", {})


# ================================================================== #
#  8. Constructor configuration                                        #
# ================================================================== #

class TestConstructorConfig:

    def test_default_http_adapter_created(self):
        driver = RestToolDriver("https://example.com/spec.json")
        assert isinstance(driver._http, HttpAdapter)

    def test_custom_http_adapter_used(self):
        adapter = HttpAdapter(verify_ssl=False, timeout=30)
        driver = RestToolDriver("https://example.com/spec.json", _http=adapter)
        assert driver._http is adapter
        assert driver._http.verify_ssl is False
        assert driver._http.timeout == 30

    def test_http_kwargs_forwarded(self):
        driver = RestToolDriver(
            "https://example.com/spec.json",
            verify_ssl=False,
            default_headers={"X-Api-Key": "secret"},
        )
        assert driver._http.verify_ssl is False
        assert driver._http.default_headers["X-Api-Key"] == "secret"

    def test_basic_auth_via_kwargs(self):
        driver = RestToolDriver(
            "https://example.com/spec.json",
            basic_user="user",
            basic_password="pass",
        )
        assert "Authorization" in driver._http.default_headers
        assert driver._http.default_headers["Authorization"].startswith("Basic ")

    def test_proxy_via_kwargs(self):
        driver = RestToolDriver(
            "https://example.com/spec.json",
            proxy_url="proxy.local",
            proxy_port=8080,
        )
        assert driver._http.proxies is not None
        assert "8080" in driver._http.proxies["http"]


# ================================================================== #
#  9. DriverMeta                                                       #
# ================================================================== #

class TestDriverMeta:

    def test_meta_attributes(self):
        driver = RestToolDriver("https://example.com/spec.json")
        assert driver.meta.name == "REST MCS ToolDriver"
        assert driver.meta.version == "0.2.0"
        assert len(driver.meta.bindings) == 1
        assert driver.meta.bindings[0].capability == "rest"
        assert driver.meta.bindings[0].adapter == "http"


# ================================================================== #
#  10. Edge cases                                                      #
# ================================================================== #

class TestEdgeCases:

    def test_empty_paths(self):
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "Empty", "version": "1.0"},
            "servers": [{"url": "https://api.example.com"}],
            "paths": {}
        }
        driver = _make_driver(spec)
        assert driver.list_tools() == []

    def test_non_http_methods_ignored(self):
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "Test", "version": "1.0"},
            "servers": [{"url": "https://api.example.com"}],
            "paths": {
                "/test": {
                    "options": {"responses": {"200": {"description": "ok"}}},
                    "head": {"responses": {"200": {"description": "ok"}}},
                    "get": {"operationId": "getTest", "responses": {"200": {"description": "ok"}}}
                }
            }
        }
        driver = _make_driver(spec)
        tools = driver.list_tools()
        assert len(tools) == 1
        assert tools[0].name == "getTest"

    def test_request_body_properties_as_tool_params(self):
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "Test", "version": "1.0"},
            "servers": [{"url": "https://api.example.com"}],
            "paths": {
                "/items": {
                    "post": {
                        "operationId": "createItem",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["title"],
                                        "properties": {
                                            "title": {"type": "string", "description": "Item title"},
                                            "count": {"type": "integer"}
                                        }
                                    }
                                }
                            }
                        },
                        "responses": {"201": {"description": "created"}}
                    }
                }
            }
        }
        driver = _make_driver(spec)
        tools = driver.list_tools()
        assert len(tools) == 1
        params = {p.name: p for p in tools[0].parameters}
        assert "title" in params
        assert params["title"].required is True
        assert "count" in params
        assert params["count"].required is False


# ================================================================== #
#  11. Healthcheck                                                     #
# ================================================================== #

class TestHealthcheck:

    def test_healthcheck_ok(self):
        driver = RestToolDriver("https://example.com/spec.json")
        with patch.object(driver._http, "head", return_value=200):
            result = driver.healthcheck()
            assert result["status"].value == "OK"

    def test_healthcheck_error(self):
        driver = RestToolDriver("https://example.com/spec.json")
        with patch.object(driver._http, "head", side_effect=ConnectionError("refused")):
            result = driver.healthcheck()
            assert result["status"].value == "ERROR"
