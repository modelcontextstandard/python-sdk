"""The **V** in MVC: every character these examples put on screen.

Nothing here knows what MCS is. It receives plain values -- a name, a text
fragment, a :class:`DriverResponse` -- and renders them. That separation is what
lets every example look and behave the same while differing only in its driver.

The one piece of *behaviour* that lives here is :meth:`ChatView.ask_consent`:
asking the user whether a tool may run is a view concern (it owns the terminal
and knows whether it is mid-line), so it is handed to ``PermissionMiddleware``
as its consent handler.
"""

from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.status import Status

from mcs.driver.core import DriverResponse


class ChatView:
    """Renders one chat session to the terminal.

    Tracks whether the cursor sits mid-line (``_open``), because a tool call can
    interrupt a streaming answer at any moment: a panel or a consent prompt must
    then start on a fresh line and resume the answer afterwards.
    """

    def __init__(self, console: Console | None = None, debug: bool = False) -> None:
        self.console = console or Console()
        self.debug = debug
        self._open = False        # a line was started with end="" and not closed
        self._status: Status | None = None   # live spinner, while nothing can be shown
        self._needs_header = False   # the next text must (re-)print "Assistant:"

    # -- session framing ------------------------------------------------------

    def banner(self, *, title: str, driver_name: str, binding: str, model: str,
               mode: str, api_base: str | None, extra: list[str] | None = None) -> None:
        info = [f"[bold cyan]{title}[/bold cyan]\n",
                f"Driver:   {driver_name}",
                f"Binding:  {binding}",
                f"Model:    {model}",
                f"Tools:    {mode}"]
        if api_base:
            info.append(f"API base: {api_base}")
        info += extra or []
        info += [f"Debug:    {'on' if self.debug else 'off'}",
                 "", "[dim]Type 'exit' or Ctrl+C to quit.[/dim]"]
        self.console.print(Panel("\n".join(info), expand=False))

    def tools_discovered(self, names: list[str]) -> None:
        self.console.print(f"[dim]Tools discovered ({len(names)}): {names}[/dim]")

    def system_prompt(self, text: str) -> None:
        if self.debug:
            self.console.print(Panel(text, title="System prompt", border_style="dim"))

    def ask_user(self) -> str | None:
        """Prompt for the next message; ``None`` means the user wants to quit."""
        self._interrupt()
        try:
            text = self.console.input("\n[bold green]You:[/bold green] ").strip()
        except (EOFError, KeyboardInterrupt):
            return None
        return None if not text or text.lower() in ("exit", "quit", "q") else text

    def ended(self) -> None:
        self.console.print("\n[dim]Chat ended.[/dim]")

    # -- the assistant's answer ----------------------------------------------

    def answer_begins(self) -> None:
        """A user turn starts: spin until there is something to show.

        The first token can take seconds, and a bare "Assistant:" with nothing
        after it reads like a hang. So the header is printed by the first piece of
        *actual* text (see :meth:`stream_text`) and until then a spinner says the
        request is in flight.
        """
        self._needs_header = True
        self._spin("waiting for the model")

    def stream_text(self, text: str) -> None:
        # Stop spinning, then decide whether this text needs a header. It does at
        # the start of a turn, and after an *interruption* -- something else printed
        # (a consent panel, a debug panel), so the answer must not run on
        # headerless. It does NOT after a mere spinner pause: nothing was printed in
        # between, so this is the same answer continuing. Held-back text that turns
        # out to be prose after all lands here, and a second "Assistant:" mid-answer
        # would suggest the model started over.
        self._spin_off()
        if self._needs_header:
            self._resume()
        print(text, end="", flush=True)
        self._open = True

    def stream_waiting(self) -> None:
        """A tool call is forming -- the driver holds its text back.

        Nothing legible exists yet (the call is half-written JSON), so instead of
        leaking dots into the answer, keep spinning with a label that says what is
        actually happening.
        """
        self._close_line()
        self._spin("a tool call is forming")

    def thinking(self, label: str = "waiting for the model") -> None:
        """Spin while a blocking request is in flight."""
        self._spin(label)

    def answer_block(self, content: str) -> None:
        """Render a complete (non-streamed) answer as Markdown."""
        self._interrupt()
        self.console.print("\n[bold blue]Assistant:[/bold blue] ", end="")
        try:
            self.console.print(Markdown(content))
        except Exception:
            self.console.print(content)

    def answer_ends(self) -> None:
        self._spin_off()
        self._close_line()

    def _close_line(self) -> None:
        if self._open:
            print()
            self._open = False

    # -- the spinner ----------------------------------------------------------

    def _spinner_name(self) -> str:
        """``dots`` reads best, but it is Braille -- a legacy Windows console on
        cp1252 raises on it. Fall back to the ASCII spinner there."""
        try:
            "⠋".encode(getattr(self.console.file, "encoding", None) or "utf-8")
        except (UnicodeEncodeError, LookupError):
            return "line"
        return "dots"

    def _spin(self, label: str) -> None:
        """Start or relabel the live spinner. No-op-safe without a TTY.

        The spinner carries the ``Assistant:`` header itself. A tool call is the
        assistant *acting*, so it belongs under that label just like the text does
        -- and the header cannot be printed separately beforehand, because the
        spinner owns its line while it runs.
        """
        text = f"[bold blue]Assistant:[/bold blue] [dim]{label}...[/dim]"
        if self._status is None:
            self._status = self.console.status(text, spinner=self._spinner_name())
            self._status.start()
        else:
            self._status.update(text)

    def _spin_off(self) -> None:
        if self._status is not None:
            self._status.stop()
            self._status = None

    # -- interruptions (panels, prompts) --------------------------------------

    def _interrupt(self) -> None:
        """Leave the answer line cleanly so something else may print.

        The spinner owns the cursor while it runs, so it has to go first --
        otherwise its live region fights with whatever prints next.

        Marks the answer as broken: whatever prints next comes between the model's
        words, so the answer needs a fresh header when it resumes.
        """
        self._spin_off()
        self._close_line()
        self._needs_header = True

    def _resume(self) -> None:
        """(Re-)open the answer line.

        The leading blank line is deliberate: it separates the answer from
        whatever interrupted it (a consent verdict, a debug panel) instead of
        letting them run together.
        """
        self.console.print("\n[bold blue]Assistant:[/bold blue] ", end="")
        self._open = True
        self._needs_header = False

    def tool_requested(self, tool_name: str, arguments: dict[str, Any]) -> None:
        """Show the call that is about to run. Always visible, not debug-only --
        the whole point of a gate is that the user sees what is being asked."""
        self._interrupt()
        args = ", ".join(f"{k}={v!r}" for k, v in arguments.items())
        self.console.print(Panel(f"[bold]{tool_name}[/bold]({args})",
                                 title="Tool call requested", border_style="yellow"))

    def ask_consent(self, tool_name: str, arguments: dict[str, Any]) -> bool:
        """Consent handler for ``PermissionMiddleware`` -- may this call run?

        Called from *inside* ``process_llm_response``, so it fires mid-stream while
        the answer line is still open. It closes that line to ask; the next piece of
        streamed text re-opens it.
        """
        self.tool_requested(tool_name, arguments)
        try:
            answer = self.console.input("[bold yellow]Allow? [y/N][/bold yellow] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = ""
        granted = answer in ("y", "yes", "j", "ja")
        self.console.print("[green]-> allowed[/green]" if granted else "[red]-> denied[/red]")
        return granted

    def tool_running(self, tool_name: str, arguments: dict[str, Any] | None = None) -> None:
        """Pre-hook handler for ``HooksMiddleware`` -- a tool is starting.

        This is how a client learns that a call is happening *without* inspecting
        the LLM output: the driver stack tells it. Rendered as a spinner label
        rather than a line of its own, so it replaces the "waiting" state instead
        of pushing the answer around.
        """
        self._spin(f"running {tool_name}")

    def auto_consent(self, tool_name: str, arguments: dict[str, Any]) -> bool:
        """Consent handler that always agrees -- but still *shows* the call.

        Same visibility as :meth:`ask_consent`, without the prompt: the gate is
        configured differently, not switched off.
        """
        self.tool_requested(tool_name, arguments)
        self.console.print("[green]-> auto-approved[/green]")
        return True

    def raw_llm_output(self, payload: dict) -> None:
        if not self.debug:
            return
        import json
        self._interrupt()
        self.console.print(Panel(json.dumps(payload, indent=2, ensure_ascii=False),
                                 title="Raw LLM output", border_style="dim"))

    def driver_response(self, dr: DriverResponse) -> None:
        """Show the per-call report (debug only). The answer line re-opens itself
        when the next chunk of text arrives."""
        if not self.debug:
            return
        self._interrupt()
        parts = [f"call_executed={dr.call_executed}  call_failed={dr.call_failed}"]
        # executed_calls is the readable surface: one line per call, so a parallel
        # batch stays legible instead of collapsing into a single blob.
        for rec in dr.executed_calls or []:
            if rec.error:
                outcome = f"[red]error:[/red] {rec.error}"
            else:
                text = str(rec.result)
                outcome = "-> " + (text[:157] + "..." if len(text) > 160 else text)
            parts.append(f"  • {rec.name}({rec.arguments}) {outcome}")
        if dr.retry_prompt:
            parts.append(f"retry_prompt: {dr.retry_prompt}")
        self.console.print(Panel("\n".join(parts), title="DriverResponse", border_style="dim"))

    # -- status notes ---------------------------------------------------------

    def warn(self, text: str) -> None:
        self._interrupt()
        self.console.print(f"[yellow]{text}[/yellow]")
