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

from collections.abc import Sequence

from mcs.driver.core import (
    DriverResponse,
    MCSDriver,
    SupportsNativeTools,
    SupportsStreaming,
)

from .llm import LLM
from .view import ChatView

#: Consecutive *failed* call attempts before giving up on a user turn.
MAX_TOOL_RETRIES = 3
#: Hard cap on tool rounds per user turn, so a model that keeps calling a tool
#: successfully can never loop forever.
MAX_TOOL_ROUNDS = 25


class ChatSession:
    """An interactive chat over one **or several** MCS drivers.

    Several drivers are not orchestrated -- they are **chained**, which is what
    the driver contract is built for. Each driver inspects the LLM output, and one
    that does not recognise the call returns an empty ``DriverResponse`` meaning
    "not mine"; the next one then looks. That pass-through is why a client can
    combine a REST driver and a web driver without either knowing about the other,
    and without any component in between.
    """

    def __init__(self, drivers: MCSDriver | Sequence[MCSDriver], model: str, *,
                 view: ChatView,
                 streaming: bool = True, native_tools: bool = True,
                 api_base: str | None = None, api_key: str | None = None,
                 title: str | None = None,
                 banner_extra: list[str] | None = None) -> None:
        self.drivers: list[MCSDriver] = (
            [drivers] if isinstance(drivers, MCSDriver) else list(drivers)
        )
        if not self.drivers:
            raise SystemExit("ChatSession needs at least one driver.")
        #: Convenience for the single-driver examples.
        self.driver = self.drivers[0]
        self.view = view
        self.streaming = streaming
        self.title = title or f"MCS Chat ({'streaming' if streaming else 'non-streaming'})"
        self.banner_extra = banner_extra
        self.api_base = api_base

        if streaming:
            mute = [d for d in self.drivers if not isinstance(d, SupportsStreaming)]
            if mute:
                raise SystemExit(
                    f"{', '.join(d.meta.name for d in mute)} does not support streaming."
                )

        # Native tool-calling when asked for AND every driver offers it: the tools
        # travel as structured schemas beside the prompt instead of inlined into
        # it. Text-prompt mode is the universal fallback -- the driver then parses
        # the call out of the model's text.
        #
        # All-or-nothing across the chain on purpose: native schemas for one driver
        # plus an inlined prompt for another would hand the model two different
        # ways to call a tool in the same conversation.
        tools: list[dict] | None = None
        # Filtered rather than all(isinstance(...)): the comprehension narrows the type,
        # so the calls below need no cast -- and the length check is the same all-or-nothing.
        natives = [d for d in self.drivers if isinstance(d, SupportsNativeTools)]
        if native_tools and len(natives) == len(self.drivers):
            contexts = [d.get_native_tool_context(model) for d in natives]
            # Deduplicate: drivers share boilerplate, and repeating it verbatim
            # per driver only spends context.
            seen: set[str] = set()
            parts: list[str] = []
            for ctx in contexts:
                if ctx.system_message and ctx.system_message not in seen:
                    seen.add(ctx.system_message)
                    parts.append(ctx.system_message)
            self.system_msg = "\n\n".join(parts)
            tools = [t for ctx in contexts for t in (ctx.tools or [])]
        else:
            self.system_msg = "\n\n".join(
                d.get_driver_system_message() for d in self.drivers
            )

        self.mode = "native tools" if tools else "text prompt"
        self.llm = LLM(model, api_base=api_base, api_key=api_key, tools=tools)
        self.messages: list[dict] = [{"role": "system", "content": self.system_msg}]

    # -- the driver chain ------------------------------------------------------

    def _offer(self, llm_output) -> DriverResponse:
        """Offer the LLM output to each driver until one owns the call.

        This is the whole of multi-driver support, and it needs nothing in
        between: a driver that does not recognise the call returns an empty
        ``DriverResponse`` -- "not mine" -- and the next one looks. Whoever
        recognises it executes it, and the round ends.

        Every driver is offered the output even after one reported
        ``call_pending``, because "a call is forming in my format" is not a claim
        of ownership -- another driver may own the finished call. Only
        ``call_executed``/``call_failed`` ends the round.

        While streaming this is genuine fan-out: all drivers see the *same*
        buffer. That is why the buffer defers dropping a handled call until the
        next chunk arrives -- every driver in the chain must have had its look
        first.
        """
        pending = False
        last: DriverResponse | None = None
        for driver in self.drivers:
            dr = driver.process_llm_response(llm_output)   # type: ignore[arg-type]
            if dr.call_executed or dr.call_failed:
                return dr
            pending = pending or dr.call_pending
            last = dr
        if last is None:
            return DriverResponse()
        # Keep the client feeding chunks rather than concluding the turn is over.
        last.call_pending = pending
        return last

    # -- session --------------------------------------------------------------

    def run(self) -> None:
        names = " + ".join(d.meta.name for d in self.drivers)
        bindings = " + ".join(
            f"{b.capability}/{b.adapter}"
            for d in self.drivers for b in d.meta.bindings
        ) or "--"
        self.view.banner(
            title=self.title,
            driver_name=names,
            binding=bindings,
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
            #
            # ONE buffer for the whole chain -- that is what makes it fan-out: every
            # driver sees the same assembled message. Any driver's factory will do,
            # because reassembly is a *provider* concern, not a driver one: the buffer
            # is MCS and every driver ships the same wire formats.
            buf = self.driver.new_stream_buffer()   # type: ignore[attr-defined]
            content = ""
            tool_ran = tool_ok = False

            for chunk in stream:
                buf.add(chunk)
                dr = self._offer(buf)                 # through the chain

                if dr.messages:                       # tool result -> back to the LLM
                    self.messages.extend(dr.messages)
                if (text := buf.text()):              # text the drivers let through
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
            dr = self._offer(llm_out)                 # through the chain

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
