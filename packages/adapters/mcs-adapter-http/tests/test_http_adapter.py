"""Tests for HttpAdapter -- constructor config, request delegation, auth, proxy."""

from __future__ import annotations

import base64
from unittest.mock import MagicMock, patch

import pytest

from mcs.adapter.http import HttpAdapter, HttpError, HttpResponse


# ================================================================== #
#  Constructor configuration                                           #
# ================================================================== #

class TestConstructor:

    def test_defaults(self):
        adapter = HttpAdapter()
        assert adapter.default_headers == {}
        assert adapter.verify_ssl is True
        assert adapter.timeout == 15
        assert adapter.proxies is None

    def test_custom_timeout(self):
        adapter = HttpAdapter(timeout=30)
        assert adapter.timeout == 30

    def test_verify_ssl_false(self):
        adapter = HttpAdapter(verify_ssl=False)
        assert adapter.verify_ssl is False

    def test_default_headers(self):
        adapter = HttpAdapter(default_headers={"X-Api-Key": "secret"})
        assert adapter.default_headers["X-Api-Key"] == "secret"

    def test_basic_auth_sets_authorization_header(self):
        adapter = HttpAdapter(basic_user="admin", basic_password="pass123")
        assert "Authorization" in adapter.default_headers
        expected = base64.b64encode(b"admin:pass123").decode()
        assert adapter.default_headers["Authorization"] == f"Basic {expected}"

    def test_basic_auth_does_not_overwrite_existing(self):
        adapter = HttpAdapter(
            default_headers={"Authorization": "Bearer tok"},
            basic_user="admin",
            basic_password="pass",
        )
        assert adapter.default_headers["Authorization"] == "Bearer tok"

    def test_proxy_config(self):
        adapter = HttpAdapter(proxy_url="proxy.local", proxy_port=8080)
        assert adapter.proxies is not None
        assert "http" in adapter.proxies
        assert "proxy.local:8080" in adapter.proxies["http"]

    def test_proxy_with_auth(self):
        adapter = HttpAdapter(
            proxy_url="proxy.local",
            proxy_port=8080,
            proxy_user="puser",
            proxy_password="ppass",
        )
        assert "puser:ppass@" in adapter.proxies["http"]

    def test_proxy_without_port_is_none(self):
        adapter = HttpAdapter(proxy_url="proxy.local")
        assert adapter.proxies is None


# ================================================================== #
#  request()                                                           #
# ================================================================== #

class TestRequest:

    @patch("mcs.adapter.http.http_adapter.requests.request")
    def test_get_request(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '{"ok": true}'
        mock_resp.content = b'{"ok": true}'
        mock_resp.headers = {"Content-Type": "application/json"}
        mock_resp.reason = "OK"
        mock_resp.encoding = "utf-8"
        mock_req.return_value = mock_resp

        adapter = HttpAdapter()
        result = adapter.request("GET", "https://example.com/api")

        assert isinstance(result, HttpResponse)
        assert result.status_code == 200
        assert result.text == '{"ok": true}'
        assert result.ok is True
        assert result.json() == {"ok": True}
        mock_req.assert_called_once_with(
            "GET",
            "https://example.com/api",
            params=None,
            json=None,
            headers={},
            timeout=15,
            verify=True,
            proxies=None,
        )

    @patch("mcs.adapter.http.http_adapter.requests.request")
    def test_post_with_json_body(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.text = '{"id": 1}'
        mock_resp.content = b'{"id": 1}'
        mock_resp.headers = {}
        mock_resp.reason = "Created"
        mock_resp.encoding = "utf-8"
        mock_req.return_value = mock_resp

        adapter = HttpAdapter()
        result = adapter.request("POST", "https://example.com/api", json_body={"name": "test"})

        assert result.ok is True
        call_kwargs = mock_req.call_args
        assert call_kwargs.kwargs["json"] == {"name": "test"}

    @patch("mcs.adapter.http.http_adapter.requests.request")
    def test_headers_merged(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "{}"
        mock_resp.content = b"{}"
        mock_resp.headers = {}
        mock_resp.reason = "OK"
        mock_resp.encoding = "utf-8"
        mock_req.return_value = mock_resp

        adapter = HttpAdapter(default_headers={"X-Default": "yes"})
        adapter.request("GET", "https://example.com", headers={"X-Extra": "val"})

        call_kwargs = mock_req.call_args
        assert call_kwargs.kwargs["headers"] == {"X-Default": "yes", "X-Extra": "val"}

    @patch("mcs.adapter.http.http_adapter.requests.request")
    def test_custom_timeout_per_call(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "{}"
        mock_resp.content = b"{}"
        mock_resp.headers = {}
        mock_resp.reason = "OK"
        mock_resp.encoding = "utf-8"
        mock_req.return_value = mock_resp

        adapter = HttpAdapter(timeout=10)
        adapter.request("GET", "https://example.com", timeout=30)

        assert mock_req.call_args.kwargs["timeout"] == 30

    @patch("mcs.adapter.http.http_adapter.requests.request")
    def test_non_2xx_does_not_raise(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.text = '{"error": "not_found"}'
        mock_resp.content = b'{"error": "not_found"}'
        mock_resp.headers = {}
        mock_resp.reason = "Not Found"
        mock_resp.encoding = "utf-8"
        mock_req.return_value = mock_resp

        adapter = HttpAdapter()
        result = adapter.request("GET", "https://example.com/missing")

        assert result.status_code == 404
        assert result.ok is False
        assert result.reason == "Not Found"

    @patch("mcs.adapter.http.http_adapter.requests.request")
    def test_raise_for_status_opt_in(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.text = "Unauthorized"
        mock_resp.content = b"Unauthorized"
        mock_resp.headers = {}
        mock_resp.reason = "Unauthorized"
        mock_resp.encoding = "utf-8"
        mock_req.return_value = mock_resp

        adapter = HttpAdapter()
        result = adapter.request("GET", "https://example.com/secret")

        with pytest.raises(HttpError, match="401 Unauthorized") as exc_info:
            result.raise_for_status()
        assert exc_info.value.status_code == 401
        assert exc_info.value.response is result


# ================================================================== #
#  head()                                                              #
# ================================================================== #

class TestHead:

    @patch("mcs.adapter.http.http_adapter.requests.head")
    def test_head_returns_status_code(self, mock_head):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_head.return_value = mock_resp

        adapter = HttpAdapter()
        code = adapter.head("https://example.com")

        assert code == 200
        mock_head.assert_called_once_with(
            "https://example.com",
            headers={},
            timeout=15,
            verify=True,
            proxies=None,
        )

    @patch("mcs.adapter.http.http_adapter.requests.head")
    def test_head_custom_timeout(self, mock_head):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_head.return_value = mock_resp

        adapter = HttpAdapter(timeout=10)
        adapter.head("https://example.com", timeout=3)

        assert mock_head.call_args.kwargs["timeout"] == 3
