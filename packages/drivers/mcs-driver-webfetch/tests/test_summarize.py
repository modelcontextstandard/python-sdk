"""The summarizer hook on fetch_page: advertised only when wired, whole-page when used.

Offline throughout: a fake connector serves the page, a fake summarizer records what it
was asked to condense. What these tests pin down is the *contract* between driver and
summarizer -- who sees how much text, which knobs apply, what the result says.
"""

from __future__ import annotations

import pytest

from mcs.driver.webfetch import SummarizerNotConfigured, WebfetchToolDriver
from mcs.types.llm import TokenUsage
from mcs.types.summarizer import Summary, SummarizerPort
from mcs.types.web import WebPage


class FakeConnector:
    """Serves one canned page, already extracted (kind='text')."""

    def __init__(self, text: str = "Absatz eins.\n\nDie Frist betraegt drei Monate.",
                 url: str = "https://example.org/doc"):
        self.page = WebPage(url=url, text=text, kind="text", title="Doc")

    def fetch(self, url: str, want: str = "text") -> WebPage:
        return self.page


class FakeSummarizer:
    """Records the condensation request; answers deterministically."""

    def __init__(self, answer: str = "Drei Monate.", truncated: bool = False,
                 usage: TokenUsage = TokenUsage()):
        self.seen: list[tuple[str, str]] = []
        self.answer = answer
        self.truncated = truncated
        self.usage = usage

    def summarize(self, text: str, query: str) -> Summary:
        self.seen.append((text, query))
        return Summary(text=self.answer, query=query, strategy="map_reduce",
                       chunks=3, truncated=self.truncated, usage=self.usage)


def _driver(**kw) -> WebfetchToolDriver:
    return WebfetchToolDriver(connector=FakeConnector(), **kw)


def _prompt_params(driver):
    [tool] = driver.list_tools()
    return [p for p in tool.parameters if p.name == "prompt"]


class TestAdvertising:
    """Same policy as allow_raw: an option the driver would refuse is not shown."""

    def test_without_summarizer_prompt_is_not_advertised(self):
        assert _prompt_params(_driver()) == []

    def test_with_summarizer_prompt_is_advertised(self):
        assert len(_prompt_params(_driver(summarizer=FakeSummarizer()))) == 1

    def test_guessing_the_parameter_names_the_fix(self):
        """Unadvertised is not unreachable -- a model may guess, a client may call
        directly. The refusal must say what to construct, not fail obscurely."""
        with pytest.raises(SummarizerNotConfigured, match="summarizer="):
            _driver().execute_tool("fetch_page",
                                   {"url": "https://x.org", "prompt": "Frist?"})


class TestCondensation:

    def test_the_summarizer_sees_the_whole_page(self):
        """The point of the path: no max_chars, no start_index -- the disposable
        context reads everything, the conversation gets the answer."""
        fake = FakeSummarizer()
        result = _driver(summarizer=fake).execute_tool(
            "fetch_page",
            {"url": "https://x.org", "prompt": "Wie lange ist die Frist?",
             "max_chars": 10, "start_index": 5})       # both must be ignored
        [(seen_text, seen_query)] = fake.seen
        assert "drei Monate" in seen_text               # full text, not 10 chars
        assert seen_query == "Wie lange ist die Frist?"
        assert result["content"] == "Drei Monate."

    def test_the_result_describes_its_own_making(self):
        result = _driver(summarizer=FakeSummarizer()).execute_tool(
            "fetch_page", {"url": "https://x.org", "prompt": "Frist?"})
        assert result["prompt"] == "Frist?"
        assert result["summary_strategy"] == "map_reduce"
        assert result["chunks_read"] == 3
        assert result["truncated"] is False
        assert result["source_chars"] > 0               # the claim check
        assert result["url"] == "https://example.org/doc"

    def test_the_condensers_cost_travels_on_the_result(self):
        """The client's window into the tool layer: what the disposable context
        measurably cost rides on the normal tool result -- input being exactly what
        the conversation did NOT pay for."""
        fake = FakeSummarizer(usage=TokenUsage(input=8_900, output=120, reasoning=40))
        result = _driver(summarizer=fake).execute_tool(
            "fetch_page", {"url": "https://x.org", "prompt": "Frist?"})
        assert result["usage"] == {"input": 8_900, "output": 120, "reasoning": 40}

    def test_unmeasured_cost_is_absent_not_zero(self):
        """A summarizer whose backend reported nothing must not put zeros into the
        result -- absent means unmeasured, and unmeasured is not free."""
        result = _driver(summarizer=FakeSummarizer()).execute_tool(
            "fetch_page", {"url": "https://x.org", "prompt": "Frist?"})
        assert "usage" not in result

    def test_a_truncated_summary_is_flagged(self):
        """The measured trap, surfaced at the tool boundary: an incomplete answer
        must never look like a short one."""
        result = _driver(summarizer=FakeSummarizer(truncated=True)).execute_tool(
            "fetch_page", {"url": "https://x.org", "prompt": "Frist?"})
        assert result["truncated"] is True

    def test_nothing_relevant_carries_a_note(self):
        result = _driver(summarizer=FakeSummarizer(answer="")).execute_tool(
            "fetch_page", {"url": "https://x.org", "prompt": "Hauptstadt von Peru?"})
        assert result["content"] == ""
        assert "not an error" in result["note"]

    def test_without_prompt_the_paging_path_is_untouched(self):
        """A wired summarizer must not change plain reads: same driver, no prompt,
        and truncation plus continuation work exactly as before."""
        fake = FakeSummarizer()
        result = _driver(summarizer=fake).execute_tool(
            "fetch_page", {"url": "https://x.org", "max_chars": 12})
        assert fake.seen == []                          # summarizer never consulted
        assert result["truncated"] is True
        assert result["next_start_index"] == 12
        assert len(result["content"]) == 12


class TestPortCompatibility:

    def test_the_real_summarizer_satisfies_what_the_driver_expects(self):
        """The driver duck-types; this pins the duck to the real Protocol so the
        two cannot drift apart silently."""
        assert isinstance(FakeSummarizer(), SummarizerPort)
