"""Fix quickstart sections in Intro.md and org profile README."""
import pathlib

def fix_file(path, old, new):
    p = pathlib.Path(path)
    content = p.read_text(encoding="utf-8")
    if old not in content:
        print(f"NOT FOUND in {path}")
        return False
    content = content.replace(old, new)
    p.write_text(content, encoding="utf-8")
    print(f"OK: {path}")
    return True

# --- Intro.md ---
old_intro = (
    "You don\u2019t need a complex setup to verify how MCS works in principle.  \n"
    "Use any LLM with web access to connect to a simple OpenAPI-enabled tool. This demonstrates the core concept.\n"
    "\n"
    "We provide a tiny FastAPI demo that exposes a **readable OpenAPI HTML spec** and a test function (`fibonacci`) that returns `2 \u00d7 Fibonacci(n)`, helping detect hallucinations.\n"
    "\n"
    "> \u2139\ufe0f Most LLMs can currently access external content only via `GET` requests and basic HTML parsing. But that\u2019s enough for this test."
)

new_intro = (
    "You don\u2019t need a complex setup to inject context into an LLM. No protocol, no wrapper server, no SDK. A well-described API and a model that can read it \u2013 that\u2019s all it takes.\n"
    "\n"
    "This demo proves exactly that. It uses **no MCS driver at all**. Instead, it shows the raw principle that MCS is built on: if an LLM can read a function description and call the endpoint, the integration is already done.\n"
    "\n"
    "We provide a tiny FastAPI service that exposes a **readable OpenAPI HTML spec** and a test function (`fibonacci`) that returns `2 \u00d7 Fibonacci(n)`, helping detect hallucinations.\n"
    "\n"
    "> \u2139\ufe0f Most LLMs can currently access external content only via `GET` requests and basic HTML parsing. But that\u2019s enough to demonstrate the concept."
)

old_shows = (
    "### What This Shows\n"
    "Even without any special MCS driver in place, modern LLMs can already interact with well-described APIs.\n"
    "The demo shows the minimal setup needed to close the gap between LLM and real-world functions.\n"
    "**This principle scales:** By standardizing function calling itself, the direct text input/output interface to LLMs, MCS makes this integration seamless and universal. Just swap in your API specs, add MCS drivers, and you have full integration in your AI app. "
)

new_shows = (
    "### What This Shows\n"
    "Even without any MCS driver in place, modern LLMs can already interact with well-described APIs. No wrapper, no protocol \u2013 just a spec and an endpoint.\n"
    "\n"
    "This is exactly the simplicity that MCS formalizes. A driver packages the spec, the prompt, and the execution logic into a reusable component. What you just did manually (read the spec, call the endpoint), the driver does automatically \u2013 for every LLM, every time.\n"
    "\n"
    "**Next step:** Run a real MCS driver with a local LLM client in Docker \u2013 see the [Python SDK](https://github.com/modelcontextstandard/python-sdk) for examples."
)

fix_file(
    r"C:\Development\Projekte\modelcontextstandard\docs\docs\Intro.md",
    old_intro, new_intro,
)
fix_file(
    r"C:\Development\Projekte\modelcontextstandard\docs\docs\Intro.md",
    old_shows, new_shows,
)

# --- Org-Page ---
old_org_intro = (
    "It is simple to verify how MCS works in principle.  \n"
    "Use any LLM with web access to connect to a simple OpenAPI-enabled tool. This demonstrates the core concept.\n"
    "\n"
    "This project provides a tiny FastAPI demo that exposes a **readable OpenAPI HTML spec** and a test function (`fibonacci`) that returns `2 \u00d7 Fibonacci(n)`, helping detect hallucinations.\n"
    "\n"
    "> \u2139\ufe0f Most LLMs can currently access external content only via `GET` requests and basic HTML parsing. But that\u2019s enough for this test."
)

new_org_intro = (
    "You don\u2019t need a complex setup to inject context into an LLM. No protocol, no wrapper server, no SDK. A well-described API and a model that can read it \u2013 that\u2019s all it takes.\n"
    "\n"
    "This demo proves exactly that. It uses **no MCS driver at all**. Instead, it shows the raw principle that MCS is built on: if an LLM can read a function description and call the endpoint, the integration is already done.\n"
    "\n"
    "We provide a tiny FastAPI service that exposes a **readable OpenAPI HTML spec** and a test function (`fibonacci`) that returns `2 \u00d7 Fibonacci(n)`, helping detect hallucinations.\n"
    "\n"
    "> \u2139\ufe0f Most LLMs can currently access external content only via `GET` requests and basic HTML parsing. But that\u2019s enough to demonstrate the concept."
)

old_org_shows = (
    "### What This Shows\n"
    "Even without anything special in place, modern LLMs can already interact with well-described APIs.\n"
    "The demo shows the minimal setup needed to close the gap between LLM and real-world functions.\n"
    "**This principle scales:** By standardizing function calling itself, the direct text input/output interface to LLMs, MCS makes this integration seamless and universal. "
)

new_org_shows = (
    "### What This Shows\n"
    "Even without any MCS driver in place, modern LLMs can already interact with well-described APIs. No wrapper, no protocol \u2013 just a spec and an endpoint.\n"
    "\n"
    "This is exactly the simplicity that MCS formalizes. A driver packages the spec, the prompt, and the execution logic into a reusable component. What you just did manually (read the spec, call the endpoint), the driver does automatically \u2013 for every LLM, every time.\n"
    "\n"
    "**Next step:** Run a real MCS driver with a local LLM client in Docker \u2013 see the [Python SDK](https://github.com/modelcontextstandard/python-sdk) for examples."
)

fix_file(
    r"C:\Development\Projekte\modelcontextstandard\github_org\.github\profile\README.md",
    old_org_intro, new_org_intro,
)
fix_file(
    r"C:\Development\Projekte\modelcontextstandard\github_org\.github\profile\README.md",
    old_org_shows, new_org_shows,
)

# Also fix the title in the org page
fix_file(
    r"C:\Development\Projekte\modelcontextstandard\github_org\.github\profile\README.md",
    "## Quickstart: See It in Action in Under 2 Minutes",
    "## Quickstart: The Idea in Under 2 Minutes",
)
