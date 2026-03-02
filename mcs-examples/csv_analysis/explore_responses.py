"""Response exploration: how do different APIs handle tool calls?

Sends the same prompt ("list CSV files") through multiple API modes
and captures the full request + response for comparison.

Modes:
  A) Tools described in system message (text-based, MCS-style)
  B) Native ``tools`` parameter (OpenAI function-calling)

Clients:
  1) Raw HTTP  (requests)
  2) litellm
  3) OpenAI Python client

Each combination x streaming/non-streaming = 12 tests total.

Usage::

    python explore_responses.py --api-base http://localhost:8000/v1 \
        --model meta-llama/Meta-Llama-3.1-8B-Instruct

All responses are saved to ``explore_results_<timestamp>.json``.
"""

from __future__ import annotations

import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Prompt constants
# ---------------------------------------------------------------------------

SYSTEM_TEXT_TOOLS = """\
You are a helpful assistant with access to the following tools:

## Available Tools

### list_csv_files
List all CSV files available in the configured data source.
Parameters: none

To call a tool, respond with ONLY a JSON object like this:
{"tool": "list_csv_files", "arguments": {}}
"""

NATIVE_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "list_csv_files",
            "description": "List all CSV files available in the configured data source.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    }
]

USER_PROMPT = "Liste alle verfügbaren CSV-Dateien auf."


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ts() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _save(results: list[dict], path: Path) -> None:
    path.write_text(json.dumps(results, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    print(f"\n>>> Saved {len(results)} results to {path}")


def _banner(label: str) -> None:
    sep = "=" * 72
    print(f"\n{sep}\n  {label}\n{sep}")


def _dump(obj: Any, label: str = "Response") -> None:
    """Pretty-print a JSON-serialisable object."""
    print(f"\n--- {label} ---")
    print(json.dumps(obj, indent=2, ensure_ascii=False, default=str))


# ---------------------------------------------------------------------------
# 1) Raw HTTP via requests
# ---------------------------------------------------------------------------

def raw_http(
    base_url: str, model: str, messages: list[dict],
    *, stream: bool = False, tools: list | None = None,
) -> dict:
    import os
    import requests

    url = f"{base_url.rstrip('/')}/chat/completions"
    body: dict[str, Any] = {"model": model, "messages": messages, "stream": stream}
    if tools:
        body["tools"] = tools

    headers = {}
    api_key = os.environ.get("OPENAI_API_KEY")
    if "api.openai.com" in base_url and api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    record: dict[str, Any] = {
        "client": "raw_http",
        "stream": stream,
        "native_tools": tools is not None,
        "request": {"url": url, "body": body},
        "ts_start": _ts(),
    }

    t0 = time.perf_counter()

    if not stream:
        resp = requests.post(url, json=body, headers=headers, timeout=120)
        resp.raise_for_status()
        data = resp.json()
        record["elapsed_s"] = round(time.perf_counter() - t0, 3)
        record["response"] = data
        record["ts_end"] = _ts()
        return record

    # streaming -- collect SSE chunks
    resp = requests.post(url, json=body, headers=headers, timeout=120, stream=True)
    resp.raise_for_status()
    chunks: list[dict] = []
    for line in resp.iter_lines():
        if not line:
            continue
        text = line.decode("utf-8", errors="replace")
        if not text.startswith("data: "):
            continue
        payload = text[6:]
        if payload.strip() == "[DONE]":
            break
        try:
            chunks.append(json.loads(payload))
        except json.JSONDecodeError:
            chunks.append({"_raw": payload})

    record["elapsed_s"] = round(time.perf_counter() - t0, 3)
    record["chunks"] = chunks
    record["chunk_count"] = len(chunks)
    record["ts_end"] = _ts()
    return record


# ---------------------------------------------------------------------------
# 2) litellm
# ---------------------------------------------------------------------------

def via_litellm(
    base_url: str, model: str, messages: list[dict],
    *, stream: bool = False, tools: list | None = None,
) -> dict:
    import os
    from litellm import completion

    # If it's OpenAI, we don't need the openai/ prefix for litellm
    litellm_model = model if "api.openai.com" in base_url else f"openai/{model}"
    
    kwargs: dict[str, Any] = {
        "model": litellm_model,
        "messages": messages,
        "stream": stream,
        "api_base": base_url,
    }
    
    api_key = os.environ.get("OPENAI_API_KEY")
    if "api.openai.com" in base_url and api_key:
        kwargs["api_key"] = api_key
    else:
        kwargs["api_key"] = "no-key"

    if tools:
        kwargs["tools"] = tools

    record: dict[str, Any] = {
        "client": "litellm",
        "stream": stream,
        "native_tools": tools is not None,
        "request": {k: v for k, v in kwargs.items() if k not in ("stream", "api_key")},
        "ts_start": _ts(),
    }

    t0 = time.perf_counter()

    if not stream:
        resp = completion(**kwargs)
        record["elapsed_s"] = round(time.perf_counter() - t0, 3)
        record["response"] = resp.model_dump() if hasattr(resp, "model_dump") else str(resp)
        record["ts_end"] = _ts()
        return record

    # streaming
    stream_resp = completion(**kwargs)
    chunks: list[dict] = []
    for chunk in stream_resp:  # type: ignore[union-attr]
        d = chunk.model_dump() if hasattr(chunk, "model_dump") else {"_raw": str(chunk)}
        chunks.append(d)

    record["elapsed_s"] = round(time.perf_counter() - t0, 3)
    record["chunks"] = chunks
    record["chunk_count"] = len(chunks)
    record["ts_end"] = _ts()
    return record


# ---------------------------------------------------------------------------
# 3) OpenAI Python client
# ---------------------------------------------------------------------------

def via_openai(
    base_url: str, model: str, messages: list[dict],
    *, stream: bool = False, tools: list | None = None,
) -> dict:
    import os
    from openai import OpenAI

    api_key = os.environ.get("OPENAI_API_KEY")
    if "api.openai.com" in base_url and api_key:
        client = OpenAI(base_url=base_url, api_key=api_key)
    else:
        client = OpenAI(base_url=base_url, api_key="no-key")

    call_kwargs: dict[str, Any] = {"model": model, "messages": messages, "stream": stream}
    if tools:
        call_kwargs["tools"] = tools

    record: dict[str, Any] = {
        "client": "openai",
        "stream": stream,
        "native_tools": tools is not None,
        "request": call_kwargs,
        "ts_start": _ts(),
    }

    t0 = time.perf_counter()

    if not stream:
        resp = client.chat.completions.create(**call_kwargs)
        record["elapsed_s"] = round(time.perf_counter() - t0, 3)
        record["response"] = resp.model_dump()
        record["ts_end"] = _ts()
        return record

    # streaming
    stream_resp = client.chat.completions.create(**call_kwargs)
    chunks: list[dict] = []
    for chunk in stream_resp:
        chunks.append(chunk.model_dump())

    record["elapsed_s"] = round(time.perf_counter() - t0, 3)
    record["chunks"] = chunks
    record["chunk_count"] = len(chunks)
    record["ts_end"] = _ts()
    return record


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

TEST_MATRIX = [
    # (label,              client_fn,   native_tools)
    ("raw_http  | text",   raw_http,    False),
    ("raw_http  | tools",  raw_http,    True),
    ("litellm   | text",   via_litellm, False),
    ("litellm   | tools",  via_litellm, True),
    ("openai    | text",   via_openai,  False),
    ("openai    | tools",  via_openai,  True),
]


def run_all(base_url: str, model: str) -> list[dict]:
    results: list[dict] = []

    for label, fn, native in TEST_MATRIX:
        for stream in (False, True):
            mode = "stream" if stream else "sync"
            tag = f"{label} | {mode}"
            _banner(tag)

            messages = [
                {"role": "system", "content": SYSTEM_TEXT_TOOLS if not native else "You are a helpful assistant."},
                {"role": "user", "content": USER_PROMPT},
            ]
            tools = NATIVE_TOOLS if native else None

            try:
                rec = fn(base_url, model, messages, stream=stream, tools=tools)
                rec["label"] = tag
                rec["status"] = "ok"

                if stream:
                    print(f"  {rec['chunk_count']} chunks in {rec['elapsed_s']}s")
                    _dump_stream_summary(rec["chunks"])
                else:
                    print(f"  completed in {rec['elapsed_s']}s")
                    _dump(rec["response"], "Full response")

            except Exception as e:
                rec = {"label": tag, "status": "error", "error": str(e), "ts": _ts()}
                print(f"  ERROR: {e}")

            results.append(rec)

    return results


def _dump_stream_summary(chunks: list[dict]) -> None:
    """Show which chunks carry content vs. tool_calls."""
    content_tokens = 0
    tool_call_chunks = 0
    first_tool_chunk_idx: int | None = None

    for i, c in enumerate(chunks):
        choices = c.get("choices", [])
        if not choices:
            continue
        delta = choices[0].get("delta", {})

        if delta.get("content"):
            content_tokens += 1
        if delta.get("tool_calls"):
            tool_call_chunks += 1
            if first_tool_chunk_idx is None:
                first_tool_chunk_idx = i

    print(f"  content chunks: {content_tokens}")
    print(f"  tool_call chunks: {tool_call_chunks}")
    if first_tool_chunk_idx is not None:
        print(f"  first tool_call at chunk #{first_tool_chunk_idx}")
        _dump(chunks[first_tool_chunk_idx], f"Chunk #{first_tool_chunk_idx} (first tool_call)")

    if chunks:
        _dump(chunks[-1], "Last chunk")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    from dotenv import load_dotenv
    load_dotenv()
    
    p = argparse.ArgumentParser(description="Explore LLM response formats across API modes")
    p.add_argument("--api-base", default="https://api.openai.com/v1",
                   help="OpenAI-compatible API base (default: https://api.openai.com/v1)")
    p.add_argument("--model", default="gpt-4o",
                   help="Model name as the server knows it (default: gpt-4o)")
    args = p.parse_args()

    print(f"API base : {args.api_base}")
    print(f"Model    : {args.model}")
    print(f"Prompt   : {USER_PROMPT}")

    results = run_all(args.api_base, args.model)

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = Path(__file__).parent / f"explore_results_{stamp}.json"
    _save(results, out)


if __name__ == "__main__":
    main()
