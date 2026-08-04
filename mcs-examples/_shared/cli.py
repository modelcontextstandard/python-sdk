"""Shared command line: the flags every example client understands.

An example adds only what is specific to its driver (a spec URL, a data
directory) -- the model, endpoint, streaming and debug flags are the same
everywhere, so a user who learned one client knows them all.
"""

from __future__ import annotations

import argparse


def base_parser(description: str, *, default_model: str = "gpt-5.5",
                streaming_default: bool = True) -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=description)
    p.add_argument("--model", default=default_model,
                   help=f"LiteLLM model identifier (default: {default_model})")
    p.add_argument("--api-base", default=None,
                   help="Custom OpenAI-compatible API base URL (e.g. http://localhost:8000/v1)")
    p.add_argument("--api-key", default=None,
                   help="API key for --api-base (default: 'no-key' when --api-base is set)")
    p.add_argument("--stream", action=argparse.BooleanOptionalAction, default=streaming_default,
                   help="Stream the answer chunk by chunk "
                        f"(default: {'on' if streaming_default else 'off'}; "
                        "pass --no-stream for one assembled response)")
    p.add_argument("--native-tools", action=argparse.BooleanOptionalAction, default=True,
                   help="Use the model's native tool-calling API "
                        "(default: on; pass --no-native-tools for text-prompt mode)")
    p.add_argument("--debug", "-d", action="store_true",
                   help="Show the system prompt, raw LLM output and DriverResponse details")
    return p
