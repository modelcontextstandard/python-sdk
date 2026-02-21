import pathlib

old_phase_c = """### Phase C \u2013 Conversation loop

In practice, a single user request may require multiple tool calls before the LLM can produce a final answer. The client therefore runs an iterative loop:

```
                    \u250c\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2510
                    \u2502                               \u25bc
User \u2500\u2500\u25ba Client \u2500\u2500\u25ba LLM \u2500\u2500\u25ba process_llm_response \u2500\u2500\u25ba tool called?
                     \u25b2              \u2502                  \u2502
                     \u2502          result              no \u2502
                     \u2514\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2518                  \u25bc
                                                 Final answer
```

1. The client sends the conversation (system prompt + message history) to the LLM.
2. The LLM responds. The client passes the response to `process_llm_response()`.
3. If the driver executed a tool call (the return value differs from the input), the client appends the LLM message and the tool result to the conversation history and returns to step 1.
4. If no tool call was detected (the return value equals the input), the LLM\u2019s response is the final answer for the user.

This loop is entirely managed by the client. The driver itself is stateless and handles one call at a time. This keeps the driver contract simple while allowing arbitrarily complex multi-step interactions."""

new_phase_c = """### Phase C \u2013 Conversation loop

In practice, a single user request may require multiple tool calls before the LLM can produce a final answer. The client therefore runs an iterative loop:

```
                    \u250c\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2510
                    \u2502                                             \u25bc
User \u2500\u2500\u25ba Client \u2500\u2500\u25ba LLM \u2500\u2500\u25ba process_llm_response \u2500\u2500\u25ba call_executed?
                     \u25b2              \u2502                       \u2502
                     \u2502          result               call_detected?
                     \u2502              \u2502                  \u2502         \u2502
                     \u2514\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2518           retry     no match
                                                       \u2502         \u2502
                                              get_retry_prompt  Final answer
                                                       \u2502
                     \u250c\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2518
                     \u2502
                     \u25bc
```

1. The client sends the conversation (system prompt + message history) to the LLM.
2. The LLM responds. The client passes the response to `process_llm_response()`.
3. If `call_executed` is true: the client appends the LLM message and the tool result to the conversation history and returns to step 1.
4. If `call_detected` is true but `call_executed` is false: the driver found a tool-call signature but could not execute it. The client appends `get_retry_prompt()` to the conversation so the LLM can correct its output, then returns to step 1.
5. If neither flag is set: no tool call was detected. The LLM\u2019s response is the final answer for the user.

The per-call state (`call_executed`, `call_detected`, `last_call_detail`) is reset at the start of every `process_llm_response()` invocation. The driver does not track conversation history \u2013 that remains the client\u2019s responsibility. This keeps the driver contract simple while allowing arbitrarily complex multi-step interactions."""

files = [
    pathlib.Path(r"C:\\Development\\Projekte\\modelcontextstandard\\docs\\docs\\Specification\\2_Core_Idea.md"),
    pathlib.Path(r"C:\\Development\\Projekte\\modelcontextstandard\\specification\\.github\\specification\\README.md"),
]

for p in files:
    content = p.read_text(encoding="utf-8")
    if old_phase_c in content:
        content = content.replace(old_phase_c, new_phase_c)
        p.write_text(content, encoding="utf-8")
        print(f"Updated: {p.name}")
    else:
        print(f"Old text not found in: {p.name}")

for p in files:
    verify = p.read_text(encoding="utf-8")
    assert "call_executed" in verify, f"Verification failed: {p.name}"
    print(f"Verified: {p.name}")
