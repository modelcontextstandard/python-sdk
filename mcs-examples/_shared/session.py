"""The **C** in MVC: the agent loop that drives model, driver and view.

One class, two loops -- streaming and blocking -- because that is genuinely the
only thing that differs between the example clients. Everything else (system
prompt, conversation history, tool rounds, guards, display) is shared, so a new
example is just a driver plus a title.

The loop is **LLM-steered and format-agnostic**: it continues while MCS reports
``call_executed``, never by looking at a provider's ``finish_reason``, and it
never inspects the LLM output for tool calls -- that is the driver's job.
"""

from __future__ import annotations

from mcs.driver.core import MCSDriver, SupportsNativeTools, SupportsStreaming

from .llm import LLM
from .view import ChatView

#: Consecutive *failed* call attempts before giving up on a user turn.
MAX_TOOL_RETRIES = 3
#: Hard cap on tool rounds per user turn, so a model that keeps calling a tool
#: successfully can never loop forever.
MAX_TOOL_ROUNDS = 25


class ChatSession:
    """An interactive chat over one MCS driver."""

    def __init__(self, driver: MCSDriver, model: str, *, view: ChatView,
                 streaming: bool = True, native_tools: bool = True,
                 api_base: str | None = None, api_key: str | None = None,
                 title: str | None = None,
                 banner_extra: list[str] | None = None) -> None:
        self.driver = driver
        self.view = view
        self.streaming = streaming
        self.title = title or f"MCS Chat ({'streaming' if streaming else 'non-streaming'})"
        self.banner_extra = banner_extra
        self.api_base = api_base

        if streaming and not isinstance(driver, SupportsStreaming):
            raise SystemExit(f"{driver.meta.name} does not support streaming.")

        # Native tool-calling when asked for AND the driver offers it: the tools
        # travel as structured schemas beside the prompt instead of inlined into
        # it. Text-prompt mode is the universal fallback -- the driver then parses
        # the call out of the model's text.
        tools = None
        if native_tools and isinstance(driver, SupportsNativeTools):
            ctx = driver.get_native_tool_context(model)
            self.system_msg = ctx.system_message
            tools = ctx.tools
        else:
            self.system_msg = driver.get_driver_system_message()

        self.mode = "native tools" if tools else "text prompt"
        self.llm = LLM(model, api_base=api_base, api_key=api_key, tools=tools)
        self.messages: list[dict] = [{"role": "system", "content": self.system_msg}]

    # -- session --------------------------------------------------------------

    def run(self) -> None:
        binding = self.driver.meta.bindings[0] if self.driver.meta.bindings else None
        self.view.banner(
            title=self.title,
            driver_name=self.driver.meta.name,
            binding=f"{binding.capability} / {binding.adapter}" if binding else "--",
            model=self.llm.model,
            mode=self.mode,
            api_base=self.api_base,
            extra=self.banner_extra,
        )
        self.view.system_prompt(self.system_msg)

        while True:
            user_input = self.view.ask_user()
            if user_input is None:
                break
            self.messages.append({"role": "user", "content": user_input})
            if self.streaming:
                self._streaming_turn()
            else:
                self._blocking_turn()
        self.view.ended()

    # -- one user turn, streamed ----------------------------------------------

    def _streaming_turn(self) -> None:
        # ONE answer block per user turn: tool rounds interrupt it but do not end
        # it ("let me look that up ..... here is what I found").
        self.view.answer_begins()
        retries = rounds = 0

        while True:
            stream = self.llm.stream(self.messages)
            # The buffer reassembles the provider's native message; the driver
            # works ON the buffer (holding a forming call) and reports status.
            buf = self.driver.new_stream_buffer()   # type: ignore[attr-defined]
            content = ""
            tool_ran = tool_ok = False

            for chunk in stream:
                buf.add(chunk)
                dr = self.driver.process_llm_response(buf)   # type: ignore[arg-type]

                if dr.messages:                       # tool result -> back to the LLM
                    self.messages.extend(dr.messages)
                if (text := buf.text()):              # text the driver let through
                    content += text
                    self.view.stream_text(text)
                elif dr.call_pending:                 # a call is building up
                    self.view.stream_waiting()

                if dr.call_executed or dr.call_failed:
                    self.view.driver_response(dr)
                    tool_ran = True
                    tool_ok = tool_ok or dr.call_executed
                    content = ""    # pre-call text already went out in dr.messages
                    # A tool call ends the model's turn. Anything streamed after it
                    # was generated blind -- before the tool ran -- so stop consuming
                    # and let the result-aware answer continue on the next turn.
                    break

            if not tool_ran:
                if content.strip():   # the final answer; the driver did not record it
                    self.messages.append({"role": "assistant", "content": content})
                self.view.answer_ends()
                return

            rounds += 1
            if rounds >= MAX_TOOL_ROUNDS:
                self.view.warn("Max tool rounds reached -- stopping.")
                return
            if tool_ok:
                retries = 0           # progress -> keep working
            else:
                retries += 1          # only failures count toward the cap
                if retries > MAX_TOOL_RETRIES:
                    self.view.warn("Tool call keeps failing -- giving up.")
                    return

    # -- one user turn, blocking ----------------------------------------------

    def _blocking_turn(self) -> None:
        retries = 0

        for _round in range(MAX_TOOL_ROUNDS):
            # A blocking call returns nothing until it is done -- spin so the wait
            # never looks like a hang.
            self.view.thinking()
            llm_out = self.llm.complete(self.messages)
            dr = self.driver.process_llm_response(llm_out)

            self.view.raw_llm_output(llm_out)
            self.view.driver_response(dr)

            if dr.messages:
                self.messages.extend(dr.messages)

            if dr.call_executed:
                retries = 0
                continue

            if dr.call_failed:
                retries += 1
                self.view.warn("Tool call failed: " + "; ".join(
                    r.error or "" for r in dr.executed_calls or []))
                if retries > MAX_TOOL_RETRIES:
                    self.view.warn("Tool call keeps failing -- giving up.")
                    return
                continue

            content = llm_out.get("content", "") or ""
            self.messages.append({"role": "assistant", "content": content})
            self.view.answer_block(content)
            return

        self.view.warn("Max tool rounds reached -- stopping.")
