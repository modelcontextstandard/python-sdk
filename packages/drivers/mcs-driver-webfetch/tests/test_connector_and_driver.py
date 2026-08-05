"""Tests for the connector (transport) and the driver (want vs. got)."""

from __future__ import annotations

import pytest

from mcs.driver.webfetch import (
    HttpPageConnector,
    RawNotAllowed,
    UnsupportedFormatError,
    WebfetchToolDriver,
)
from mcs.types.http import HttpResponse
from mcs.types.web import WebPage

HTML = "<html><head><title>T</title></head><body><p>Hello world.</p></body></html>"


class _FakeHttp:
    def __init__(self, body=HTML, *, content_type="text/html", status=200, url=None):
        self.body, self.content_type, self.status, self.url = body, content_type, status, url

    def request(self, method, url, **kw):
        return HttpResponse(status_code=self.status, text=self.body,
                            headers={"Content-Type": self.content_type},
                            url=self.url or url)


class TestConnectorReportsWhatItGot:
    """The connector is transport: it fetches and declares, it does not interpret."""

    def test_html_is_announced_as_html(self):
        page = HttpPageConnector(_FakeHttp()).fetch("https://x.com", want="text")
        assert page.kind == "html"
        assert page.text == HTML          # untouched -- conversion is the driver's job

    def test_non_html_is_announced_as_text(self):
        body = '{"a": 1}'
        page = HttpPageConnector(_FakeHttp(body, content_type="application/json")).fetch(
            "https://x.com/api")
        assert page.kind == "text"
        assert page.text == body

    def test_reports_final_url_after_redirect(self):
        page = HttpPageConnector(_FakeHttp(url="https://x.com/final")).fetch("https://x.com/start")
        assert page.url == "https://x.com/final"

    def test_http_error_raises(self):
        with pytest.raises(Exception):
            HttpPageConnector(_FakeHttp("nope", status=404)).fetch("https://x.com")


class _CannedConnector:
    """A service-style connector: returns already-extracted content."""

    def __init__(self, kind="markdown", text="# Title\n\nBody."):
        self.kind, self.text = kind, text
        self.wants: list[str] = []

    def fetch(self, url, *, want="text"):
        self.wants.append(want)
        return WebPage(url=url, text=self.text, kind=self.kind, title="Canned")


class TestWantVersusGot:

    def test_html_backend_gets_converted(self):
        out = WebfetchToolDriver(HttpPageConnector(_FakeHttp())).execute_tool(
            "fetch_page", {"url": "https://x.com"})
        assert "Hello world." in out["content"]
        assert "<p>" not in out["content"]
        assert out["title"] == "T"

    def test_raw_returns_markup_untouched(self):
        out = WebfetchToolDriver(HttpPageConnector(_FakeHttp()), allow_raw=True).execute_tool(
            "fetch_page", {"url": "https://x.com", "format": "raw"})
        assert out["content"] == HTML

    def test_service_content_is_passed_through_not_re_extracted(self):
        """Re-extracting what a service already extracted can only lose information."""
        conn = _CannedConnector()
        out = WebfetchToolDriver(conn).execute_tool(
            "fetch_page", {"url": "https://x.com", "format": "markdown"})
        assert out["content"] == "# Title\n\nBody."
        assert conn.wants == ["markdown"]        # the wish was forwarded

    def test_raw_from_a_service_backend_fails_loudly(self):
        """Silently downgrading would answer a question the caller did not ask."""
        driver = WebfetchToolDriver(_CannedConnector(), allow_raw=True)
        with pytest.raises(UnsupportedFormatError, match="raw markup is not available"):
            driver.execute_tool("fetch_page", {"url": "https://x.com", "format": "raw"})

    def test_invalid_format_rejected(self):
        driver = WebfetchToolDriver(_CannedConnector())
        with pytest.raises(ValueError, match="format must be one of"):
            driver.execute_tool("fetch_page", {"url": "https://x.com", "format": "pdf"})


class TestToolSurface:

    def test_exposes_exactly_one_tool(self):
        tools = WebfetchToolDriver(_CannedConnector()).list_tools()
        assert [t.name for t in tools] == ["fetch_page"]

    def test_parameters_documented(self):
        tool = WebfetchToolDriver(_CannedConnector()).list_tools()[0]
        params = {p.name: p for p in tool.parameters}
        assert set(params) == {"url", "format", "max_chars", "start_index"}
        assert params["format"].schema["enum"] == ["text", "markdown"]  # raw is opt-in
        for p in tool.parameters:
            assert p.description, f"{p.name} needs a description -- the model reads it"

    def test_missing_url_rejected(self):
        with pytest.raises(ValueError, match="requires a 'url'"):
            WebfetchToolDriver(_CannedConnector()).execute_tool("fetch_page", {})

    def test_unknown_tool_rejected(self):
        with pytest.raises(ValueError, match="not found"):
            WebfetchToolDriver(_CannedConnector()).execute_tool("crawl", {"url": "https://x.com"})


class TestPaging:

    def test_truncation_tells_the_model_how_to_continue(self):
        conn = _CannedConnector(kind="text", text="abcdefghij")
        out = WebfetchToolDriver(conn).execute_tool(
            "fetch_page", {"url": "https://x.com", "max_chars": 4})
        assert out["truncated"] is True
        assert out["total_chars"] == 10
        assert out["next_start_index"] == 4

    def test_no_hints_when_complete(self):
        conn = _CannedConnector(kind="text", text="short")
        out = WebfetchToolDriver(conn).execute_tool("fetch_page", {"url": "https://x.com"})
        assert out["truncated"] is False
        assert "next_start_index" not in out

    def test_paging_reassembles_the_document(self):
        conn = _CannedConnector(kind="text", text="0123456789")
        driver = WebfetchToolDriver(conn)
        a = driver.execute_tool("fetch_page", {"url": "https://x.com", "max_chars": 4})
        b = driver.execute_tool("fetch_page", {"url": "https://x.com", "max_chars": 4,
                                               "start_index": a["next_start_index"]})
        assert a["content"] + b["content"] == "01234567"

    def test_driver_is_orchestratable(self):
        driver = WebfetchToolDriver(_CannedConnector())
        assert "orchestratable" in driver.meta.capabilities
        assert driver.meta.bindings[0].capability == "webfetch"


class TestRawIsOptIn:
    """Raw hands the model everything on the page -- script bodies, hidden
    elements, comments. Useful for inspecting a page, and a prompt-injection
    surface no sanitiser can close without destroying the format. So: opt-in."""

    def test_raw_is_not_advertised_by_default(self):
        """The model should not learn an option it will be refused -- that costs a
        round trip per conversation to rediscover."""
        tool = WebfetchToolDriver(_CannedConnector()).list_tools()[0]
        fmt = {p.name: p for p in tool.parameters}["format"]
        assert fmt.schema["enum"] == ["text", "markdown"]
        assert "raw" not in tool.description

    def test_raw_is_advertised_when_allowed(self):
        tool = WebfetchToolDriver(_CannedConnector(), allow_raw=True).list_tools()[0]
        fmt = {p.name: p for p in tool.parameters}["format"]
        assert fmt.schema["enum"] == ["text", "markdown", "raw"]
        assert "raw" in tool.description

    def test_raw_is_refused_by_default_even_if_guessed(self):
        """Unadvertised is not unreachable: a model may guess, a client may call
        execute_tool directly."""
        driver = WebfetchToolDriver(HttpPageConnector(_FakeHttp()))
        with pytest.raises(RawNotAllowed, match="not permitted"):
            driver.execute_tool("fetch_page", {"url": "https://x.com", "format": "raw"})

    def test_text_and_markdown_unaffected(self):
        driver = WebfetchToolDriver(HttpPageConnector(_FakeHttp()))
        assert "Hello world." in driver.execute_tool(
            "fetch_page", {"url": "https://x.com"})["content"]
