"""Tests for HttpAdapter -- constructor config, request delegation, auth, proxy."""

from __future__ import annotations

import base64
from unittest.mock import MagicMock, patch

import pytest

from mcs.adapter.http import HttpAdapter


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
        mock_resp.text = '{"ok": true}'
        mock_resp.raise_for_status = MagicMock()
        mock_req.return_value = mock_resp

        adapter = HttpAdapter()
        result = adapter.request("GET", "https://example.com/api")

        assert result == '{"ok": true}'
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
        mock_resp.text = '{"id": 1}'
        mock_resp.raise_for_status = MagicMock()
        mock_req.return_value = mock_resp

        adapter = HttpAdapter()
        adapter.request("POST", "https://example.com/api", json_body={"name": "test"})

        call_kwargs = mock_req.call_args
        assert call_kwargs.kwargs["json"] == {"name": "test"}

    @patch("mcs.adapter.http.http_adapter.requests.request")
    def test_headers_merged(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.text = "{}"
        mock_resp.raise_for_status = MagicMock()
        mock_req.return_value = mock_resp

        adapter = HttpAdapter(default_headers={"X-Default": "yes"})
        adapter.request("GET", "https://example.com", headers={"X-Extra": "val"})

        call_kwargs = mock_req.call_args
        assert call_kwargs.kwargs["headers"] == {"X-Default": "yes", "X-Extra": "val"}

    @patch("mcs.adapter.http.http_adapter.requests.request")
    def test_custom_timeout_per_call(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.text = "{}"
        mock_resp.raise_for_status = MagicMock()
        mock_req.return_value = mock_resp

        adapter = HttpAdapter(timeout=10)
        adapter.request("GET", "https://example.com", timeout=30)

        assert mock_req.call_args.kwargs["timeout"] == 30

    @patch("mcs.adapter.http.http_adapter.requests.request")
    def test_raise_for_status_called(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = Exception("404")
        mock_req.return_value = mock_resp

        adapter = HttpAdapter()
        with pytest.raises(Exception, match="404"):
            adapter.request("GET", "https://example.com/missing")


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
