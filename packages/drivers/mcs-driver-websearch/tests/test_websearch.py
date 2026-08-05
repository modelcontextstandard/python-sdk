"""Tests for the search connector (wire mapping) and driver (tool surface)."""

from __future__ import annotations

import json

import pytest

from mcs.driver.websearch import (
    TavilySearchConnector,
    WebsearchDriver,
    WebsearchToolDriver,
)
from mcs.types.http import HttpResponse
from mcs.types.web import SearchResult

TAVILY_RESPONSE = {
    "query": "mcs",
    "answer": None,
    "results": [
        {
            "title": "Model Context Standard (MCS)",
            "url": "https://github.com/modelcontextstandard",
            "content": "MCS is a lightweight standard...",   # engine excerpt
            "score": 1.0,
            "raw_content": None,
            "thumbnail": "https://img.example/t.png",
        },
        {
            "title": "Second hit",
            "url": "https://example.com/2",
            "content": "excerpt two",
            "score": 0.5,
            "raw_content": "the full page text",
            "published_date": "2026-08-01",
        },
    ],
    "images": [],
    "response_time": 0.7,
}


class _FakeHttp:
    def __init__(self, payload=None, status=200):
        self.payload = TAVILY_RESPONSE if payload is None else payload
        self.status = status
        self.calls: list[dict] = []

    def request(self, method, url, **kw):
        self.calls.append({"method": method, "url": url, "json_body": kw.get("json_body")})
        return HttpResponse(status_code=self.status, text=json.dumps(self.payload),
                            headers={"Content-Type": "application/json"}, url=url)


class TestWireMapping:

    def test_snippet_and_content_are_kept_apart(self):
        """Easy to get backwards: Tavily's `content` is the *excerpt*, while
        `raw_content` is the full page -- and only present when requested."""
        conn = TavilySearchConnector("k", base_url="https://svc", adapter=_FakeHttp())
        results, _ = conn.search("mcs")
        assert results[0].snippet == "MCS is a lightweight standard..."
        assert results[0].content is None
        assert results[1].content == "the full page text"

    def test_maps_the_common_fields(self):
        conn = TavilySearchConnector("k", base_url="https://svc", adapter=_FakeHttp())
        results, _ = conn.search("mcs")
        r = results[0]
        assert isinstance(r, SearchResult)
        assert r.url == "https://github.com/modelcontextstandard"
        assert r.title == "Model Context Standard (MCS)"
        assert r.score == 1.0
        assert results[1].published == "2026-08-01"

    def test_unknown_extras_are_kept_not_dropped(self):
        """A richer backend should lose nothing while common fields stay stable."""
        conn = TavilySearchConnector("k", base_url="https://svc", adapter=_FakeHttp())
        results, _ = conn.search("mcs")
        assert results[0].meta["thumbnail"] == "https://img.example/t.png"

    def test_include_answer_is_not_sent_unless_asked(self):
        """Opt-in: synthesis costs the backend an LLM call, and deployments differ
        in how they respond when it is unavailable."""
        http = _FakeHttp()
        TavilySearchConnector("k", base_url="https://svc", adapter=http).search("mcs")
        assert "include_answer" not in http.calls[0]["json_body"]

        http2 = _FakeHttp()
        TavilySearchConnector("k", base_url="https://svc", adapter=http2,
                              include_answer=True).search("mcs")
        assert http2.calls[0]["json_body"]["include_answer"] is True

    def test_optional_filters_are_omitted_when_unset(self):
        http = _FakeHttp()
        TavilySearchConnector("k", base_url="https://svc", adapter=http).search("mcs")
        body = http.calls[0]["json_body"]
        for key in ("include_domains", "exclude_domains", "time_range"):
            assert key not in body

    def test_filters_are_forwarded(self):
        http = _FakeHttp()
        TavilySearchConnector("k", base_url="https://svc", adapter=http).search(
            "mcs", include_domains=["a.com"], exclude_domains=["b.com"], time_range="week")
        body = http.calls[0]["json_body"]
        assert body["include_domains"] == ["a.com"]
        assert body["exclude_domains"] == ["b.com"]
        assert body["time_range"] == "week"

    def test_http_error_raises(self):
        conn = TavilySearchConnector("k", base_url="https://svc",
                                     adapter=_FakeHttp({"detail": "nope"}, status=401))
        with pytest.raises(Exception):
            conn.search("mcs")


class _FakeConnector:
    def __init__(self, results=None, answer=None):
        self.results = results if results is not None else [
            SearchResult(url="https://a.com", title="A", snippet="sa"),
            SearchResult(url="https://b.com", title="B", snippet="sb",
                         content="x" * 9000),
        ]
        self.answer = answer
        self.calls: list[dict] = []

    def search(self, query, **kw):
        self.calls.append({"query": query, **kw})
        return self.results, self.answer


class TestToolSurface:

    def test_exposes_one_tool(self):
        assert [t.name for t in WebsearchToolDriver(_FakeConnector()).list_tools()] == ["web_search"]

    def test_verticals_are_a_parameter_not_extra_tools(self):
        """Four near-identical tools would bloat the prompt for a distinction the
        backend already models behind one endpoint."""
        tool = WebsearchToolDriver(_FakeConnector()).list_tools()[0]
        params = {p.name: p for p in tool.parameters}
        assert params["topic"].schema["enum"] == ["general", "news"]
        for p in tool.parameters:
            assert p.description, f"{p.name} needs a description -- the model reads it"

    def test_missing_query_rejected(self):
        with pytest.raises(ValueError, match="requires a 'query'"):
            WebsearchToolDriver(_FakeConnector()).execute_tool("web_search", {})

    def test_unknown_topic_rejected(self):
        with pytest.raises(ValueError, match="topic must be one of"):
            WebsearchToolDriver(_FakeConnector()).execute_tool(
                "web_search", {"query": "x", "topic": "videos"})

    def test_unknown_tool_rejected(self):
        with pytest.raises(ValueError, match="not found"):
            WebsearchToolDriver(_FakeConnector()).execute_tool("crawl", {"query": "x"})


class TestExecution:

    def test_returns_hits_with_snippets(self):
        out = WebsearchToolDriver(_FakeConnector()).execute_tool(
            "web_search", {"query": "mcs"})
        assert out["count"] == 2
        assert out["results"][0]["url"] == "https://a.com"
        assert out["results"][0]["snippet"] == "sa"
        assert "content" not in out["results"][0]      # not requested

    def test_content_only_when_requested_and_capped(self):
        conn = _FakeConnector()
        out = WebsearchToolDriver(conn, content_chars=100).execute_tool(
            "web_search", {"query": "mcs", "include_content": True})
        assert conn.calls[0]["include_content"] is True
        body = out["results"][1]
        assert len(body["content"]) == 100
        assert body["content_truncated"] is True

    def test_says_so_when_some_results_have_no_content(self):
        """Otherwise the model cannot tell "not fetched" from "page was empty"."""
        out = WebsearchToolDriver(_FakeConnector()).execute_tool(
            "web_search", {"query": "mcs", "include_content": True})
        assert "note" in out

    def test_max_results_is_clamped_not_rejected(self):
        """An over-large ask is reasonable; failing the call would waste a round
        trip over a detail we can simply fix."""
        conn = _FakeConnector()
        WebsearchToolDriver(conn).execute_tool(
            "web_search", {"query": "mcs", "max_results": 999})
        assert conn.calls[0]["max_results"] == 20
        WebsearchToolDriver(conn).execute_tool(
            "web_search", {"query": "mcs", "max_results": 0})
        assert conn.calls[1]["max_results"] == 5      # falsy -> default

    def test_answer_is_passed_through_when_present(self):
        out = WebsearchToolDriver(_FakeConnector(answer="synthesised")).execute_tool(
            "web_search", {"query": "mcs"})
        assert out["answer"] == "synthesised"

    def test_no_answer_key_when_backend_gave_none(self):
        out = WebsearchToolDriver(_FakeConnector()).execute_tool(
            "web_search", {"query": "mcs"})
        assert "answer" not in out


class TestDriver:

    def test_standalone_driver_delegates(self):
        d = WebsearchDriver(_tooldriver=WebsearchToolDriver(_FakeConnector()))
        assert [t.name for t in d.list_tools()] == ["web_search"]
        assert d.execute_tool("web_search", {"query": "mcs"})["count"] == 2

    def test_driver_is_standalone_and_orchestratable(self):
        d = WebsearchDriver(_tooldriver=WebsearchToolDriver(_FakeConnector()))
        assert "standalone" in d.meta.capabilities
        assert "orchestratable" in d.meta.capabilities
        assert d.meta.bindings[0].capability == "websearch"

    def test_system_prompt_describes_the_tool(self):
        d = WebsearchDriver(_tooldriver=WebsearchToolDriver(_FakeConnector()))
        assert "web_search" in d.get_driver_system_message()
