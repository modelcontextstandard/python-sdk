"""Turn retrieved markup into the shape the caller asked for.

The adapter's job ends with the content; deciding what it *means* is a strategy,
which is where MCS already keeps this kind of choice (``PromptStrategy`` encodes
a call, ``ExtractionStrategy`` recognises one). Content reduction is the same
shape of problem: several approaches exist, none is universally right, so the
choice must be swappable rather than compiled in.

**HTML is a minefield, so established libraries do the dangerous parts.** Writing
markdown conversion by hand was attempted here and failed three times in one
sitting -- void elements swallowing the document, inline whitespace welding words
together, a link wrapping an icon consuming everything after it. All three were
*silent*: the unit tests stayed green and only a live page revealed them. That is
the argument for :mod:`nh3` and :mod:`markdownify` rather than more hand-rolled
parsing.

What ships here:

``StripExtractor``
    Dependency-free baseline. Removes what is provably not content (scripts,
    styles, nav, forms) and keeps the rest. Never loses content; leaves noise in.

``ReadableExtractor``
    Delegates to :mod:`trafilatura` when installed. Highest precision in
    published benchmarks -- and precisely therefore wrong on listing pages, where
    it keeps "the article" and discards the list that *was* the content.

``MarkdownExtractor``
    :mod:`nh3` sanitises, :mod:`markdownify` converts.

``BestOfExtractor``
    Picks between text extractors using the mechanism read from `agent-fetch`_
    (MIT): the length ratio is a **veto** that disqualifies an untrustworthy
    primary, and only then does length decide among the survivors. Note what that
    is *not* -- nothing is filtered away. Two complete candidates exist and one is
    chosen.

.. _agent-fetch: https://github.com/teng-lin/agent-fetch
"""

from __future__ import annotations

import logging
import re
from html import unescape
from html.parser import HTMLParser
from typing import Protocol, runtime_checkable

logger = logging.getLogger(__name__)

#: Void elements: no end tag exists and they hold no text. They must **never**
#: open a skip region -- the closing tag that would end it never comes, so the
#: rest of the document silently disappears. A real page carries ~50 ``<meta>``
#: tags; treating them as containers emptied every page while the title still
#: came through, which made the parser look healthy. Two debugging rounds.
_VOID = frozenset({
    "area", "base", "br", "col", "embed", "hr", "img", "input",
    "link", "meta", "param", "source", "track", "wbr",
})
#: Elements HTML lets you leave *unclosed*. Same hazard, same rule.
_OPTIONAL_END = frozenset({"option", "li", "p", "td", "tr", "th", "dt", "dd"})
#: Text inside these is never content. ``head`` is absent on purpose: it holds
#: ``<title>``, and its noisy children are dropped by name anyway.
_DROP = frozenset({
    "script", "style", "noscript", "template", "svg", "canvas", "iframe",
    "object", "select", "datalist",
})
#: Chrome rather than content.
_DROP_CHROME = frozenset({"nav", "header", "footer", "aside", "form"})
#: Force a line break so lists and tables stay legible once the tags are gone.
_BLOCK = frozenset({
    "p", "div", "section", "article", "main", "br", "hr", "pre", "blockquote",
    "h1", "h2", "h3", "h4", "h5", "h6", "li", "tr", "td", "th", "dt", "dd",
    "table", "ul", "ol", "dl",
})

NEWLINE = "\n"


class MarkdownUnavailable(RuntimeError):
    """Markdown was requested but its libraries are not installed.

    Raised rather than degrading to a hand-rolled converter: a silent downgrade
    would produce less safe output that nobody can see is less safe.
    """


@runtime_checkable
class ContentStrategy(Protocol):
    """Reduce HTML to one representation."""

    #: What this strategy produces: ``"text"`` or ``"markdown"``.
    kind: str

    def convert(self, html: str, url: str) -> tuple[str, str | None]:
        """Return ``(content, title)``."""
        ...


def _tidy(text: str) -> str:
    text = text.replace("\r\n", NEWLINE).replace("\r", NEWLINE)
    text = re.sub(r"[ \t\f\v]+", " ", text)
    text = re.sub(r" *\n *", NEWLINE, text)
    return re.sub(r"\n{3,}", NEWLINE * 2, text).strip()


def title_from_html(html: str) -> str | None:
    """The document's own ``<title>``.

    Worth having as a fallback: extractors that read metadata often prefer
    ``og:title``, which on many sites is the *site* name rather than the page's.
    """
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    return unescape(m.group(1)).strip() if m else None


class _Walker(HTMLParser):
    """Collect visible text: skip non-content subtrees, break blocks, catch the title.

    Only used for the dependency-free ``strip`` baseline. Markdown goes through
    markdownify -- see :class:`MarkdownExtractor` for why.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._skip = 0
        self._skip_tag: str | None = None
        self._parts: list[str] = []
        self._in_title = False
        self.title: str | None = None

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag in _VOID:
            if not self._skip and tag in _BLOCK:
                self._parts.append(NEWLINE)
            return
        if self._skip:
            # Count nesting of the *same* tag, so an inner <div> inside a skipped
            # <nav> does not end the skip early.
            if tag == self._skip_tag:
                self._skip += 1
            return
        if (tag in _DROP or tag in _DROP_CHROME) and tag not in _OPTIONAL_END:
            self._skip, self._skip_tag = 1, tag
            return
        if tag == "title":
            self._in_title = True
            return
        if tag in _BLOCK:
            self._parts.append(NEWLINE)

    def handle_endtag(self, tag: str) -> None:
        if self._skip:
            if tag == self._skip_tag:
                self._skip -= 1
                if not self._skip:
                    self._skip_tag = None
            return
        if tag == "title":
            self._in_title = False
            return
        if tag in _BLOCK:
            self._parts.append(NEWLINE)

    def handle_data(self, data: str) -> None:
        if self._skip:
            return
        if not data.strip():
            # Whitespace *between inline elements* carries meaning. Dropping it
            # welds words together: "<span>alpha</span> <span>beta</span>" became
            # "alphabeta", silently corrupting the text the model reads.
            if data and self._parts and not self._parts[-1].endswith((" ", NEWLINE)):
                self._parts.append(" ")
            return
        if self._in_title:
            if self.title is None:
                self.title = data.strip()
            return
        self._parts.append(data)

    def result(self) -> str:
        return _tidy("".join(self._parts))


def _walk(html: str) -> tuple[str, str | None]:
    w = _Walker()
    try:
        w.feed(html)
        w.close()
    except Exception:          # HTMLParser is lenient; a fetch must never die here
        logger.debug("malformed markup while walking", exc_info=True)
    return w.result(), w.title


class StripExtractor:
    """Keep everything that is not provably chrome. Loses nothing, keeps noise."""

    kind = "text"
    name = "strip"

    def convert(self, html: str, url: str) -> tuple[str, str | None]:
        return _walk(html)


class MarkdownExtractor:
    """HTML to Markdown via **nh3 + markdownify** -- not by hand.

    Both halves are deliberate.

    :mod:`nh3` (Python binding to Rust's *ammonia*) sanitises first. It drops
    ``javascript:``/``data:`` hrefs, event-handler attributes and ``<script>``,
    and adds ``rel="noopener noreferrer"``. This matters because the markdown
    goes to an LLM whose answer is often rendered *as markdown* in a chat UI --
    an unsanitised href travels from an attacker's page, through the model, into
    a user's browser as a clickable link.

    Note that ``bleach``, the name most people reach for, is **end of life**:
    6.4.0 (June 2026) was the final release, the repository is archived, and the
    announcement states there will be no further releases *including for security
    issues*, because html5lib underneath is unmaintained. nh3 is the maintained
    successor and roughly 20x faster.

    :mod:`markdownify` then converts, and handles the cases a hand-rolled version
    got wrong here -- void elements, inline whitespace, links without text -- plus
    nested lists and tables, which it could not do at all.

    Raises :class:`MarkdownUnavailable` when the libraries are missing rather than
    silently falling back to something less safe.
    ``pip install mcs-driver-webfetch[markdown]``
    """

    kind = "markdown"
    name = "markdown"

    #: Removed **with their content**, not merely unwrapped.
    #:
    #: This has to happen in nh3, not in markdownify: markdownify's ``strip=``
    #: drops the *tag* and keeps the text inside it, so a stripped ``<footer>``
    #: still contributes "Imprint · Terms · Privacy" to the output. ``nh3``'s
    #: ``clean_content_tags`` removes the subtree.
    DROP_WITH_CONTENT = {"script", "style", "noscript", "iframe", "object",
                         "embed", "template", "svg", "canvas", "form",
                         "nav", "header", "footer", "aside",
                         # read out separately; in the body it is a duplicate
                         "title"}

    def convert(self, html: str, url: str) -> tuple[str, str | None]:
        try:
            import nh3                                          # noqa: PLC0415
            from markdownify import markdownify                 # noqa: PLC0415
        except ImportError as exc:
            raise MarkdownUnavailable(
                "format='markdown' needs nh3 and markdownify: "
                "pip install mcs-driver-webfetch[markdown]"
            ) from exc

        title = title_from_html(html)
        # nh3 first: sanitise *and* drop chrome subtrees. Whatever survives is
        # safe to turn into markdown.
        #
        # A tag may not appear in both sets, so the allow-list is the default
        # minus everything we drop wholesale (nh3 raises otherwise -- a helpful
        # error rather than a silent contradiction).
        allowed = (nh3.ALLOWED_TAGS | {"h1", "h2", "h3", "h4", "h5", "h6"}
                   ) - self.DROP_WITH_CONTENT
        cleaned = nh3.clean(
            html,
            tags=allowed,
            clean_content_tags=self.DROP_WITH_CONTENT,
        )
        md = markdownify(cleaned, heading_style="ATX")
        return _tidy(md), title


class ReadableExtractor:
    """Readability-grade extraction via trafilatura, when it is installed.

    Returns ``("", None)`` when unavailable or when it finds nothing, so a caller
    can fall back instead of handing the model an empty page.
    """

    kind = "text"
    name = "readable"

    def convert(self, html: str, url: str) -> tuple[str, str | None]:
        try:
            import trafilatura                                  # noqa: PLC0415
        except ImportError:
            return "", None
        try:
            text = trafilatura.extract(html, url=url, include_comments=False,
                                       include_tables=True, favor_recall=True)
            if not text:
                return "", None
            meta = trafilatura.extract_metadata(html)
            return text.strip(), (getattr(meta, "title", None) if meta else None)
        except Exception:
            logger.warning("trafilatura failed on %s", url, exc_info=True)
            return "", None


class BestOfExtractor:
    """Run several extractors and keep the most complete trustworthy result.

    The mechanism is taken from `agent-fetch`_ -- **read from its source**, not
    from its description, because the two differ in an important way. Summaries
    say "readability wins unless another strategy finds 2x more". The code does
    something subtler::

        if (densityLen > readLen * COMPARATOR_LENGTH_RATIO && densityLen >= GOOD_CONTENT_LENGTH) {
            effectiveReadability = null;     // disqualify, don't outvote
        }
        // ...then: among candidates over the good threshold, the longest wins

    The ratio is a **veto, not a selector**. It does not ask "which result is
    bigger", it asks "did readability misjudge this page so badly that it should
    not be trusted at all". Only afterwards does length decide, and only among
    results that cleared a quality bar.

    That ordering matters. Length alone would pick raw stripping every time, since
    keeping the navigation always yields more characters than removing it.

    Verified against measurements on real pages:

    ==================== ======= ========== =========================== ==========
    page                 strip   readable   decision                    picked
    ==================== ======= ========== =========================== ==========
    GitHub trending      13 410         371 readable < 500 -> vetoed    strip
    Cloudflare article    9 008       8 237 readable fine, 1.1x < 2x    readable
    ==================== ======= ========== =========================== ==========

    On the listing page readability had kept 1 of 13 repositories; on the article
    it correctly dropped navigation that stripping left in. One rule, both right.

    .. _agent-fetch: https://github.com/teng-lin/agent-fetch
    """

    kind = "text"
    name = "auto"

    #: A result worth considering. Below this an extractor has effectively failed.
    GOOD_CONTENT_LENGTH = 500
    #: Fallback bar, used when nothing reaches "good".
    MIN_CONTENT_LENGTH = 200
    #: How much more a challenger must find before the primary is distrusted.
    COMPARATOR_RATIO = 2.0

    def __init__(self, primary: ContentStrategy | None = None,
                 challenger: ContentStrategy | None = None,
                 ratio: float | None = None) -> None:
        self.primary = primary or ReadableExtractor()
        self.challenger = challenger or StripExtractor()
        self.ratio = self.COMPARATOR_RATIO if ratio is None else ratio

    def convert(self, html: str, url: str) -> tuple[str, str | None]:
        p_text, p_title = self.primary.convert(html, url)
        c_text, c_title = self.challenger.convert(html, url)
        p_len, c_len = len(p_text), len(c_text)

        # Metadata is composed independently of who wins the content: a strategy
        # can read the title correctly while misreading the body. agent-fetch does
        # the same via composeMetadata().
        title = p_title or c_title

        trusted = p_len >= self.GOOD_CONTENT_LENGTH
        if trusted and c_len > p_len * self.ratio and c_len >= self.GOOD_CONTENT_LENGTH:
            logger.info("%s found %dx more than %s on %s -- distrusting it",
                        self.challenger.name, c_len // max(p_len, 1),
                        self.primary.name, url)
            trusted = False

        if trusted:
            return p_text, title
        if c_len >= self.MIN_CONTENT_LENGTH or c_len >= p_len:
            return c_text, title
        return p_text, title        # challenger produced nothing usable either


#: Name -> strategy, for configuration by string.
STRATEGIES = {
    "strip": StripExtractor,
    "readable": ReadableExtractor,
    "auto": BestOfExtractor,
    "markdown": MarkdownExtractor,
}
