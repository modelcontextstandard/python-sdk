"""The shared mechanics of a catalogue-backed :class:`~mcs.types.llm.ModelInfoProvider`.

A catalogue is one JSON document describing many models -- megabytes that change on the
scale of releases, not requests. So the mechanics are always the same: fetch the
document lazily over the client's injected transport, keep it, answer every lookup from
memory, and never let a failure escape -- ``None`` is the answer for an unknown model,
a dead network, and a reshaped schema alike.

:class:`ModelInfoCatalog` is that mechanic, and deliberately public: a client with its
own model database -- a company-internal service, a curated file -- subclasses it and
implements one method::

    class HouseCatalog(ModelInfoCatalog):
        def __init__(self, _http=None):
            super().__init__("https://models.internal/api.json", _http=_http)

        def describe(self, model):
            entry = (self._load() or {}).get(model)
            return ModelInfo(context_window=entry["window"]) if entry else None

The shipped subclasses wrap the two public catalogues this package was measured
against: :class:`~mcs.adapter.llm.info.LiteLLMInfoProvider` and
:class:`~mcs.adapter.llm.info.ModelsDevInfoProvider`.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from mcs.adapter.http import HttpAdapter

logger = logging.getLogger(__name__)

#: Sent when this module builds its own transport. Measured necessity, not politeness:
#: models.dev answers 403 to a client without a User-Agent.
_USER_AGENT = "mcs-adapter-llm"


class ModelInfoCatalog:
    """Fetch one JSON catalogue lazily, keep it, never raise.

    One fetch per instance. A failed fetch is remembered too: ``describe()`` is called
    per run by design, and a dead network should cost one attempt, not one per call.
    A client wanting a retry constructs a fresh provider.

    Subclasses implement ``describe(model) -> ModelInfo | None`` on top of
    :meth:`_load`, which returns the parsed document or ``None``.
    """

    def __init__(self, url: str, *, timeout: int = 60,
                 _http: HttpAdapter | None = None) -> None:
        self.url = url
        self.timeout = timeout
        headers = {"User-Agent": _USER_AGENT}
        self._http = _http or HttpAdapter(default_headers=headers, timeout=timeout)
        # With an injected transport the header travels per request instead, so the
        # client's own defaults survive rather than being replaced.
        self._extra_headers = {} if _http is None else headers
        self._data: dict[str, Any] | None = None
        self._attempted = False

    def _load(self) -> dict[str, Any] | None:
        if not self._attempted:
            self._attempted = True
            try:
                resp = self._http.request(
                    "GET", self.url,
                    headers=self._extra_headers or None, timeout=self.timeout,
                )
                if resp.status_code < 400:
                    data = json.loads(resp.text)
                    if isinstance(data, dict):
                        self._data = data
            except Exception:  # noqa: BLE001 -- knowledge lookup; None IS the answer
                logger.debug("catalog: %s yielded nothing", self.url, exc_info=True)
        return self._data

    @staticmethod
    def _modalities(value: Any) -> tuple[str, ...] | None:
        if isinstance(value, list) and value and all(isinstance(m, str) for m in value):
            return tuple(value)
        return None
