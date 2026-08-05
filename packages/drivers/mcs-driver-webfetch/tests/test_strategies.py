"""Tests for the content strategies -- extraction, markdown, and the veto rule."""

from __future__ import annotations

from mcs.driver.webfetch.strategies import (
    BestOfExtractor,
    MarkdownExtractor,
    StripExtractor,
    title_from_html,
)

PAGE = """<html>
<head><title>My Page</title><meta charset="utf-8"><meta name="a" content="b"><link rel="x" href="y"></head>
<body>
  <nav>Home About Contact</nav>
  <script>var tracking = 1;</script>
  <style>.x { color: red }</style>
  <main>
    <h1>Heading</h1>
    <p>First paragraph.</p>
    <ul><li>alpha</li><li>beta</li></ul>
    <p>See <a href="https://example.com/doc">the docs</a> for more.</p>
  </main>
  <footer>Imprint</footer>
</body></html>"""


class TestStripExtractor:

    def test_keeps_content_drops_chrome_and_code(self):
        text, title = StripExtractor().convert(PAGE, "https://x.com")
        assert title == "My Page"
        assert "First paragraph." in text and "alpha" in text
        assert "tracking" not in text            # script
        assert "color: red" not in text          # style
        assert "Home About Contact" not in text  # nav
        assert "Imprint" not in text             # footer

    def test_void_elements_do_not_swallow_the_document(self):
        """Regression: <meta> has no end tag.

        Treating it as a skippable container opened a region that never closed,
        so everything after the first <meta> vanished -- while the title still
        came through, which made the parser look healthy. A real page carries
        ~50 of them. Cost two debugging rounds.
        """
        html = ("<html><head>" + "<meta name='x' content='y'>" * 50 +
                "<title>T</title></head><body><p>SURVIVES</p></body></html>")
        text, title = StripExtractor().convert(html, "https://x.com")
        assert "SURVIVES" in text
        assert title == "T"

    def test_unclosed_optional_end_tag_does_not_swallow_the_rest(self):
        """<option> may legally omit its end tag -- same hazard as void elements."""
        html = "<html><body><select><option>A<option>B</select><p>SURVIVES</p></body></html>"
        text, _ = StripExtractor().convert(html, "https://x.com")
        assert "SURVIVES" in text

    def test_malformed_markup_does_not_raise(self):
        text, _ = StripExtractor().convert("<html><body><p>ok<div><span>unclosed", "https://x.com")
        assert "ok" in text

    def test_blocks_do_not_run_together(self):
        text, _ = StripExtractor().convert("<p>one</p><p>two</p>", "https://x.com")
        assert "onetwo" not in text


class TestMarkdownExtractor:

    def test_preserves_structure(self):
        md, title = MarkdownExtractor().convert(PAGE, "https://x.com")
        assert title == "My Page"
        assert "# Heading" in md
        assert "alpha" in md and "beta" in md          # list markers are markdownify's choice
        assert "[the docs](https://example.com/doc)" in md

    def test_handles_tables_and_nesting(self):
        """Beyond what the hand-rolled converter could do at all."""
        md, _ = MarkdownExtractor().convert(
            "<table><tr><th>H</th></tr><tr><td>1</td></tr></table>"
            "<ul><li>a<ul><li>a1</li></ul></li></ul>", "https://x.com")
        assert "| H |" in md and "| 1 |" in md
        assert "a1" in md

    def test_still_drops_non_content(self):
        md, _ = MarkdownExtractor().convert(PAGE, "https://x.com")
        assert "tracking" not in md
        assert "Imprint" not in md


class _Fixed:
    """A strategy returning a canned result, to drive the selection rule."""

    kind = "text"

    def __init__(self, text: str, title: str | None = None, name: str = "fixed") -> None:
        self._text, self._title, self.name = text, title, name

    def convert(self, html, url):
        return self._text, self._title


class TestBestOfSelection:
    """The rule read from agent-fetch's source: the ratio is a veto, not a vote.

    It does not ask which result is bigger -- it asks whether the primary
    misjudged the page so badly that it should not be trusted. Only then does the
    challenger take over. Length alone would pick raw stripping every time, since
    keeping navigation always yields more characters than removing it.
    """

    def test_listing_page_primary_below_threshold_is_vetoed(self):
        """Measured: readability returned 371 chars for a 13-entry listing."""
        best = BestOfExtractor(primary=_Fixed("x" * 371, "T"),
                               challenger=_Fixed("y" * 13410))
        text, _ = best.convert("<html></html>", "https://x.com")
        assert len(text) == 13410      # readability distrusted -> strip wins

    def test_article_primary_is_kept_when_lengths_are_comparable(self):
        """Measured: 8 237 vs 9 008 -- stripping is longer, but only by noise."""
        best = BestOfExtractor(primary=_Fixed("x" * 8237, "T"),
                               challenger=_Fixed("y" * 9008))
        text, _ = best.convert("<html></html>", "https://x.com")
        assert len(text) == 8237       # longer != better

    def test_challenger_needs_both_ratio_and_threshold(self):
        """A challenger under the good threshold cannot veto, however relatively big."""
        best = BestOfExtractor(primary=_Fixed("x" * 600, "T"),
                               challenger=_Fixed("y" * 499))
        text, _ = best.convert("<html></html>", "https://x.com")
        assert len(text) == 600

    def test_challenger_wins_when_far_ahead(self):
        best = BestOfExtractor(primary=_Fixed("x" * 600, "T"),
                               challenger=_Fixed("y" * 5000))
        text, _ = best.convert("<html></html>", "https://x.com")
        assert len(text) == 5000

    def test_title_survives_even_when_its_producer_loses(self):
        """Metadata is composed separately: a strategy can read the title well
        while misreading the body. agent-fetch does the same via composeMetadata."""
        best = BestOfExtractor(primary=_Fixed("x" * 100, "Good Title"),
                               challenger=_Fixed("y" * 9000, None))
        text, title = best.convert("<html></html>", "https://x.com")
        assert len(text) == 9000
        assert title == "Good Title"


def test_title_from_html():
    assert title_from_html("<html><head><title>Hi &amp; bye</title></head></html>") == "Hi & bye"
    assert title_from_html("<html><body>no title</body></html>") is None


class TestLinkSafety:
    """Markdown goes to an LLM, whose answer often gets rendered as markdown in a
    chat UI. An unsanitised href therefore travels from an attacker's page,
    through the model, into a user's browser as a clickable link."""

    def test_javascript_uri_is_dropped_but_text_kept(self):
        md, _ = MarkdownExtractor().convert(
            '<a href="javascript:alert(1)">Click me</a>', "https://x.com")
        assert "javascript:" not in md
        assert "Click me" in md          # readable, but inert

    def test_whitespace_evasion_in_scheme(self):
        """"java\tscript:" is a real-world evasion -- browsers ignore the tab."""
        md, _ = MarkdownExtractor().convert(
            '<a href="java\tscript:alert(1)">Sneaky</a>', "https://x.com")
        assert "script:alert" not in md

    def test_data_uri_is_dropped(self):
        md, _ = MarkdownExtractor().convert(
            '<a href="data:text/html,<script>x</script>">D</a>', "https://x.com")
        assert "data:text/html" not in md

    def test_safe_links_survive(self):
        md, _ = MarkdownExtractor().convert(
            '<a href="https://ok.example/p">Good</a>', "https://x.com")
        assert "[Good](https://ok.example/p)" in md

    def test_relative_links_survive(self):
        md, _ = MarkdownExtractor().convert('<a href="/docs">Rel</a>', "https://x.com")
        assert "[Rel](/docs)" in md


class TestInlineWhitespace:

    def test_words_do_not_weld_together(self):
        """Regression: whitespace between inline elements was dropped, turning
        "<span>alpha</span> <span>beta</span>" into "alphabeta" -- a silent
        corruption of the text the model reads."""
        text, _ = StripExtractor().convert(
            "<p><span>alpha</span> <span>beta</span></p>", "https://x.com")
        assert "alpha beta" in text

    def test_no_spurious_space_at_block_starts(self):
        text, _ = StripExtractor().convert("<p>one</p>\n<p>two</p>", "https://x.com")
        assert not text.startswith(" ")

    def test_link_without_text_does_not_swallow_the_document(self):
        """Regression: a link wrapping only an icon has no text.

        Closing the link mode on "did we collect text?" left it open forever, so
        everything after such a link vanished. All unit tests stayed green -- the
        live page revealed it: markdown returned 0 of 13 repositories.
        """
        md, _ = MarkdownExtractor().convert(
            '<p>before</p><a href="https://x.com"><svg></svg></a><p>AFTER</p>',
            "https://x.com")
        assert "AFTER" in md
