"""Two chained drivers, one consent gate: every tool call needs the user's OK.

Two things at once here, and they are independent.

**Chaining.** The client holds *two* drivers -- a ``RestDriver`` on GitHub's
OpenAPI spec and the composite ``WebDriver`` (search + fetch) -- and simply offers
each LLM response to both. A driver that does not recognise the call returns an
empty ``DriverResponse`` meaning "not mine", and the next one looks. No
orchestrator, no registry, no component in between: the pass-through is part of
the driver contract, which is exactly what makes drivers composable by the
client.

The model therefore sees four tools from two unrelated backends and picks. Ask
for something the GitHub API cannot answer -- trending repositories, say -- and
watch it fall back to searching and reading a page instead.

**The gate.** ``PermissionMiddleware`` lives *inside* a driver and wraps
``execute_tool``: it receives the pending call with its arguments, asks a consent
handler, and either continues or short-circuits with a structured
``permission_denied`` result. Nothing is executed on denial and no exception
escapes -- the model reads the refusal as a normal tool result and adapts.

Because middleware lives inside a driver, a chain of two needs it on both. The
same instance can be shared: middleware holds configuration, not per-call state.

Three things are worth noticing:

* **The client loop is unchanged.** Compare it with any other example -- same
  ``ChatSession``. Consent is configuration, and so is the second driver.
* **It works identically while streaming.** The middleware runs inside
  ``process_llm_response``, so the prompt appears mid-stream, right when a driver
  is about to execute -- and the answer continues afterwards.
* **`format="raw"` is not offered** unless ``--allow-raw`` is passed. While off,
  the model is never told the option exists.

The consent handler is the *view*: it owns the terminal and knows whether it is
mid-line, so it can interrupt a streaming answer cleanly.

Usage:
    python chat.py                     # streaming (default)
    python chat.py --no-stream         # one assembled response per turn
    python chat.py --debug             # + raw LLM output and DriverResponse
    python chat.py --allow-all         # answers the gate automatically
    python chat.py --allow-raw         # also expose format="raw"

    # Condensation: a second, cheap model reads whole pages so the conversation
    # only pays for answers. The full local setup:
    python chat.py --allow-all --summarize-model qwen3:4b \
        --summarize-effort none --summarize-window 32768

    # Cloud condenser (one call per page, needs OPENAI_API_KEY in .env):
    python chat.py --allow-all --summarize-model gpt-5.6 \
        --summarize-url https://api.openai.com/v1 --summarize-window 1000000

Configuration (environment or .env):
    MCS_SEARCH_URL      base URL of a Tavily-compatible search service
    MCS_SEARCH_KEY      its API key
    TAVILY_API_KEY      used instead when MCS_SEARCH_* are unset (hosted Tavily)
    MCS_SUMMARIZE_MODEL / MCS_SUMMARIZE_URL     condensation model and endpoint
    MCS_SUMMARIZE_KEY      its API key; falls back to OPENAI_API_KEY (local: none)
    MCS_SUMMARIZE_EFFORT   reasoning_effort of the condenser ('none' recommended)
    MCS_SUMMARIZE_PROMPTS  your prompt TOML: sparse override, per-model variants

Requires:
    pip install mcs-driver-web mcs-permission litellm rich python-dotenv
    # optional, for better extraction and safe markdown:
    pip install mcs-driver-web[full]

Try asking:
    "What are the top 3 trending GitHub repositories this week?"
    -- the search API has no trending endpoint, so the model has to find the
    page and read it. Watch which URL it decides to fetch.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from _shared import ChatSession, ChatView, base_parser  # noqa: E402

from mcs.driver.rest import RestDriver  # noqa: E402
from mcs.driver.web import WebDriver  # noqa: E402
from mcs.permission.middleware import PermissionMiddleware  # noqa: E402


GITHUB_SPEC = (
    "https://raw.githubusercontent.com/github/rest-api-description"
    "/main/descriptions/api.github.com/api.github.com.json"
)
DEFAULT_TAGS = ["search"]


def main() -> None:
    load_dotenv()
    p = base_parser("MCS chat over two chained drivers, with a consent gate")
    p.add_argument("--url", default=GITHUB_SPEC, help="OpenAPI spec URL for the REST driver")
    p.add_argument("--include-tags", nargs="*", default=None,
                   help="Only expose operations with these OpenAPI tags")
    p.add_argument("--search-url", default=os.environ.get("MCS_SEARCH_URL"),
                   help="Base URL of a Tavily-compatible search service "
                        "(default: $MCS_SEARCH_URL, else hosted Tavily)")
    p.add_argument("--search-key",
                   default=os.environ.get("MCS_SEARCH_KEY")
                   or os.environ.get("TAVILY_API_KEY"),
                   help="API key for the search service "
                        "(default: $MCS_SEARCH_KEY or $TAVILY_API_KEY)")
    p.add_argument("--allow-raw", action="store_true",
                   help="Expose format='raw' on fetch_page (off by default: raw "
                        "hands the model every script and comment on the page)")
    p.add_argument("--summarize-model", default=os.environ.get("MCS_SUMMARIZE_MODEL"),
                   help="Model id for page condensation (e.g. qwen3:4b). Enables "
                        "fetch_page's prompt parameter: the whole page is read by "
                        "THIS model and only the answer enters the conversation. "
                        "(default: $MCS_SUMMARIZE_MODEL, unset = off)")
    p.add_argument("--summarize-url",
                   default=os.environ.get("MCS_SUMMARIZE_URL", "http://localhost:11434/v1"),
                   help="Chat-Completions endpoint for --summarize-model "
                        "(default: local Ollama)")
    p.add_argument("--summarize-effort",
                   default=os.environ.get("MCS_SUMMARIZE_EFFORT"),
                   help="reasoning_effort for the condensation model. 'none' is the "
                        "right call here: condensation is extraction, not "
                        "deliberation -- a small thinker can spend thousands of "
                        "tokens reasoning and drop instructions on the way. Values "
                        "are model-dependent (Ollama maps it onto qwen3's thinking "
                        "switch; GPT-5 accepts none/low/medium/high/xhigh). "
                        "(default: $MCS_SUMMARIZE_EFFORT, unset = backend default)")
    p.add_argument("--summarize-prompts",
                   default=os.environ.get("MCS_SUMMARIZE_PROMPTS"),
                   help="Your own prompt TOML for the summarizer (sparse override of "
                        "its shipped prompts/default.toml; [prompts.\"model:qwen*\"] "
                        "sections tune per model and follow the model automatically). "
                        "(default: $MCS_SUMMARIZE_PROMPTS, unset = shipped defaults)")
    p.add_argument("--summarize-window", type=int, default=None,
                   help="Context window of the condensation model. Unset, the "
                        "summarizer asks the endpoint itself (describe, once per "
                        "model), else assumes 4096 and learns. Set it when you know "
                        "the SERVING truth better than the backend states: Ollama's "
                        "effective window is its num_ctx, NOT the model card it "
                        "reports -- beyond num_ctx it truncates silently (gross "
                        "clipping is detected via usage and relearned).")
    p.add_argument("--allow-all", action="store_true",
                   help="Auto-approve every call (to contrast with the interactive gate)")
    args = p.parse_args()

    if not args.search_key:
        raise SystemExit(
            "No search API key. Set MCS_SEARCH_KEY (with MCS_SEARCH_URL for a "
            "self-hosted service) or TAVILY_API_KEY, in the environment or a .env file."
        )

    view = ChatView(debug=args.debug)

    tags = args.include_tags if args.include_tags is not None else (
        DEFAULT_TAGS if args.url == GITHUB_SPEC else None
    )
    github = RestDriver(url=args.url, include_tags=tags)

    # Condensation is configuration, like consent: injected, never a silent
    # default. The summarizer's LLM is a SECOND model beside the conversation's --
    # typically a small local one -- whose context is disposable: it reads whole
    # pages so the conversation only ever pays for answers.
    summarizer = None
    if args.summarize_model:
        from mcs.adapter.llm.completion import CompletionLLMAdapter
        from mcs.adapter.llm.info import ModelsDevInfoProvider
        from mcs.types.summarizer import LLMSummarizer

        # Every knob sits where its knowledge sits: effort and the wire dialect on
        # the ADAPTER (properties of talking to this model), window and prompts on
        # the SUMMARIZER (planning and wording). The model id is passed to neither
        # a second time -- the summarizer asks the port per run, so prompt variants
        # in a --summarize-prompts file follow the model automatically. The window
        # works the same way: unset, the summarizer asks the port itself (describe(),
        # once per model) and keeps its nets. The flag is for when the developer
        # knows the serving truth better than the backend states it -- Ollama serves
        # its num_ctx, not the model card.
        summarizer = LLMSummarizer(
            CompletionLLMAdapter(
                args.summarize_model, 
                base_url=args.summarize_url,
                # Same pattern as the search key: a dedicated variable wins, the
                # well-known one is the fallback. Local servers need neither.
                api_key=os.environ.get("MCS_SUMMARIZE_KEY") or os.environ.get("OPENAI_API_KEY"),                
                model_info=ModelsDevInfoProvider(),                
                reasoning_effort=args.summarize_effort,
            ),
            context_window=args.summarize_window,
            prompts=args.summarize_prompts,
        )

    web = WebDriver(api_key=args.search_key, base_url=args.search_url,
                    allow_raw=args.allow_raw, summarizer=summarizer)

    # Two independent drivers, chained by the client. Neither knows about the
    # other; a call one does not recognise passes through to the next. That is
    # the driver contract doing the work -- no orchestrator, no registry.
    drivers = [github, web]
    view.tools_discovered([t.name for d in drivers for t in d.list_tools()])

    # The gate goes on *each* driver: middleware lives inside a driver, so a
    # chain of two needs two. Sharing one instance is fine -- middleware holds
    # configuration, not per-call state.
    #
    # Both handlers *show* the pending call; only one of them asks. That is the
    # contrast worth seeing: --allow-all does not switch the gate off, it answers
    # it automatically, and the middleware is in the chain either way.
    gate = PermissionMiddleware(
        consent_handler=view.auto_consent if args.allow_all else view.ask_consent
    )
    for d in drivers:
        d.add_middleware(gate)

    where = args.search_url or "api.tavily.com"
    ChatSession(
        drivers, args.model, view=view,
        streaming=args.stream, native_tools=args.native_tools,
        api_base=args.api_base, api_key=args.api_key,
        title="MCS Chat (two drivers, consent gate)",
        banner_extra=[
            f"Search:   {where}",
            f"Consent:  {'auto-approve' if args.allow_all else 'ask the user'}",
            f"Raw HTML: {'allowed' if args.allow_raw else 'not offered'}",
            "Condense: " + (
                f"{args.summarize_model} @ {args.summarize_url}"
                + (f"  window={args.summarize_window:,}" if args.summarize_window
                   else "  window=ask the endpoint, else learn")
                + (f"  effort={args.summarize_effort}" if args.summarize_effort else "")
                + (f"  prompts={Path(args.summarize_prompts).name}"
                   if args.summarize_prompts else "")
                if args.summarize_model else "off (prompt= not offered)"),
        ],
    ).run()


if __name__ == "__main__":
    main()
