"""Composite ToolDriver: search the web and read pages, through one driver.

The same shape as ``MailToolDriver`` (mailread + mailsend): two capabilities that
are built, configured and deployed separately, presented to the LLM as one set of
tools.

Why they are separate underneath and joined here:

* They **fail differently.** A search backend runs out of quota; a fetch backend
  hits a CAPTCHA. Bundling them would mean one outage takes both down.
* They are **configured differently.** Search needs an API key and a service URL;
  fetch needs a transport, and possibly a browser.
* They are **useful alone.** An agent with a known URL never searches; a research
  agent may only need excerpts.

Joined, they give the model the pattern it actually wants: *find sources, then
read the promising ones* -- two tools, one driver, no orchestration on the client
side.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

from mcs.driver.core import DriverBinding, DriverMeta, MCSToolDriver, Tool


@dataclass(frozen=True)
class _WebToolDriverMeta(DriverMeta):
    id: str = "b7a1c3d5-web-4005-9000-webtooldriver1"
    name: str = "Web MCS ToolDriver"
    version: str = "0.1.0"
    bindings: tuple[DriverBinding, ...] = (
        DriverBinding(capability="websearch", adapter="*", spec_format="Custom"),
        DriverBinding(capability="webfetch", adapter="*", spec_format="Custom"),
    )
    supported_llms: None = None
    capabilities: tuple[str, ...] = ("orchestratable",)


class WebToolDriver(MCSToolDriver):
    """Composite ToolDriver stacking websearch + webfetch.

    Accepts pre-built ToolDrivers, or builds them from keyword arguments.

    Parameters
    ----------
    api_key, base_url :
        Passed to the search backend. ``base_url`` points at any
        Tavily-compatible service (Tavily itself, a self-hosted instance).
    allow_raw :
        Permit ``format="raw"`` on the fetch half. Off by default -- while off,
        the format is not advertised to the model at all.
    search_kwargs, fetch_kwargs :
        Forwarded to the respective ToolDriver constructors.
    _search_driver, _fetch_driver :
        Inject pre-built ToolDrivers (testing, custom setups).
    """

    meta: DriverMeta = _WebToolDriverMeta()

    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        allow_raw: bool = False,
        search_kwargs: dict[str, Any] | None = None,
        fetch_kwargs: dict[str, Any] | None = None,
        _search_driver: MCSToolDriver | None = None,
        _fetch_driver: MCSToolDriver | None = None,
    ) -> None:
        if _search_driver is not None:
            self._search = _search_driver
        else:
            from mcs.driver.websearch import WebsearchToolDriver

            kw = dict(search_kwargs or {})
            if api_key is not None:
                kw.setdefault("api_key", api_key)
            if base_url is not None:
                kw.setdefault("base_url", base_url)
            self._search = WebsearchToolDriver(**kw)

        if _fetch_driver is not None:
            self._fetch = _fetch_driver
        else:
            from mcs.driver.webfetch import WebfetchToolDriver

            self._fetch = WebfetchToolDriver(allow_raw=allow_raw, **(fetch_kwargs or {}))

        # tool name -> owning driver
        self._dispatch: Dict[str, MCSToolDriver] = {}
        for part in (self._search, self._fetch):
            for tool in part.list_tools():
                if tool.name in self._dispatch:
                    # Two halves claiming one name would make dispatch arbitrary
                    # and the failure would only show up at call time.
                    raise ValueError(
                        f"Tool name collision on '{tool.name}' between the search "
                        f"and fetch halves of WebToolDriver."
                    )
                self._dispatch[tool.name] = part

    # -- MCSToolDriver contract ------------------------------------------------

    def list_tools(self) -> List[Tool]:
        return self._search.list_tools() + self._fetch.list_tools()

    def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        part = self._dispatch.get(tool_name)
        if part is None:
            raise ValueError(f"Tool '{tool_name}' not found.")
        return part.execute_tool(tool_name, arguments)
