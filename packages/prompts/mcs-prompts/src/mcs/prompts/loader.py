"""Prompt loading for MCS -- the mechanism, never the prompts.

The MCS rule: **no prompt is hardcoded.** Every word a component says to a model is
data -- tunable per model, replaceable by the developer -- because prompt engineering is
real, per-model work (Cursor maintains distinct prompts per model family; the tuning
that helps a 4B local model is noise to a frontier model, and vice versa).

This package deliberately contains **no prompts**. The prompts live with their owners:
each package ships its defaults as package data (``prompts/default.toml`` next to its
code), exactly like the core ships its tool-call codec TOML. What lives here, once, is
the loading that every owner would otherwise reimplement:

    from mcs.prompts import load_prompts

    bundle = load_prompts(
        "mcs.types.summarizer",          # whose defaults
        override="./my_prompts.toml",    # optional: the developer's own
    )
    prompts = bundle.resolve(model="qwen3:4b")   # per RUN, not per construction
    prompts["stuff"]                             # -> template string

**Loading and resolving are separate on purpose** -- the Java ``ResourceBundle`` idea,
with the model id in the role of the locale. Which texts apply depends on the model,
and the model can change *between calls* (an agent switches, a router port falls back),
so a consumer loads its bundle once and resolves per run, asking its ``LLMPort`` --
which names the model currently behind it -- for the id. Resolution is cached per id.

The TOML convention:

    [prompts]
    stuff = "Question: {query} ..."      # base templates

    [prompts."model:qwen*"]              # variant, fnmatch pattern on the model id
    stuff = "... preserve the order ..."

Precedence, weakest to strongest: package base -> package model variants -> override
base -> override model variants. Within one file, later matching variant sections win
over earlier ones.

This module has **zero** third-party dependencies (``tomllib`` is stdlib).
"""

from __future__ import annotations

import tomllib
from collections.abc import Mapping
from fnmatch import fnmatchcase
from importlib.resources import files as pkg_files
from pathlib import Path
from typing import Iterator

_MODEL_PREFIX = "model:"


class PromptSet(Mapping[str, str]):
    """The resolved templates: a read-only mapping ``name -> template string``.

    A thin type rather than a bare dict for one reason: a missing prompt must fail
    *helpfully*. A component asking for a template the developer's override renamed
    gets the available names, not a bare KeyError.
    """

    def __init__(self, templates: dict[str, str], *,
                 package: str | None = None, model: str | None = None) -> None:
        self._templates = dict(templates)
        #: Where the defaults came from -- carried for error messages and debugging.
        self.package = package
        #: Which model id selected variants (``None`` = base only).
        self.model = model

    def __getitem__(self, name: str) -> str:
        try:
            return self._templates[name]
        except KeyError:
            raise KeyError(
                f"No prompt named {name!r} in the set loaded from "
                f"{self.package or 'the given templates'}; available: "
                f"{sorted(self._templates)}"
            ) from None

    def __iter__(self) -> Iterator[str]:
        return iter(self._templates)

    def __len__(self) -> int:
        return len(self._templates)

    def __repr__(self) -> str:  # pragma: no cover -- debugging nicety
        return (f"PromptSet({sorted(self._templates)}, package={self.package!r}, "
                f"model={self.model!r})")


def _split_table(table: dict, *, where: str) -> tuple[dict[str, str], list[tuple[str, dict[str, str]]]]:
    """Separate a ``[prompts]`` table into base templates and model variants.

    String values are base templates. Sub-tables named ``model:<pattern>`` are
    variants. Anything else is a mistake worth naming now rather than a template that
    silently never loads.
    """
    base: dict[str, str] = {}
    variants: list[tuple[str, dict[str, str]]] = []
    for key, value in table.items():
        if isinstance(value, str):
            base[key] = value
        elif isinstance(value, dict) and key.startswith(_MODEL_PREFIX):
            bad = [k for k, v in value.items() if not isinstance(v, str)]
            if bad:
                raise ValueError(
                    f"Model section {key!r} in {where} may only contain template "
                    f"strings; found non-string entries: {bad}"
                )
            variants.append((key[len(_MODEL_PREFIX):], dict(value)))
        else:
            raise ValueError(
                f"Unexpected entry {key!r} in the [prompts] table of {where}: expected "
                f"a template string or a [prompts.\"model:<pattern>\"] section."
            )
    return base, variants


def _table_of(data: dict, *, where: str) -> dict:
    table = data.get("prompts")
    if table is None or not isinstance(table, dict):
        raise ValueError(f"{where} has no [prompts] table -- nothing to load.")
    return table


class PromptBundle:
    """Every prompt layer, held once -- resolved lazily, per model id, per run.

    The split between loading and resolving is the whole point: which texts apply
    depends on the model, and the model may change between calls (an agent switches, a
    router port falls back). A consumer therefore keeps the bundle and calls
    :meth:`resolve` each run with whatever its ``LLMPort`` currently names.
    Validation happened at load; resolution is a cached dictionary merge.
    """

    def __init__(
        self,
        layers: list[tuple[dict[str, str], list[tuple[str, dict[str, str]]]]],
        *,
        package: str | None = None,
    ) -> None:
        self._layers = layers
        self.package = package
        self._cache: dict[str | None, PromptSet] = {}

    def resolve(self, model: str | None = None) -> PromptSet:
        """The templates in force for *model* (``None`` = base only). Cached per id.

        Precedence, weakest to strongest, across the loaded layers: package base ->
        package model variants -> override base -> override model variants.
        """
        cached = self._cache.get(model)
        if cached is not None:
            return cached
        templates: dict[str, str] = {}
        for base, variants in self._layers:
            templates.update(base)
            if model:
                for pattern, variant in variants:
                    if fnmatchcase(model, pattern):
                        templates.update(variant)
        resolved = PromptSet(templates, package=self.package, model=model)
        self._cache[model] = resolved
        return resolved


def load_prompts(
    package: str,
    resource: str = "prompts/default.toml",
    *,
    override: str | Path | Mapping[str, str] | None = None,
) -> PromptBundle:
    """Load *package*'s shipped prompts plus developer overrides into a bundle.

    Parameters
    ----------
    package :
        Import path of the package whose defaults to load (``"mcs.types.summarizer"``).
        The prompts belong to their component; this function only fetches them.
    resource :
        Path of the TOML inside that package.
    override :
        The developer's own prompts: a TOML file path (same ``[prompts]`` layout,
        model sections allowed) or a flat mapping ``name -> template``. Overrides are
        *sparse* -- only the names present replace the defaults.

    The model id is deliberately **not** a parameter here: it belongs to
    :meth:`PromptBundle.resolve`, per run, because the model behind a port can change
    while the bundle lives on.
    """
    where = f"{package}/{resource}"
    try:
        raw = pkg_files(package).joinpath(*resource.split("/")).read_bytes()
    except (FileNotFoundError, ModuleNotFoundError) as exc:
        raise FileNotFoundError(
            f"No prompt defaults at {where}: {exc}. A package that loads prompts "
            f"ships them as package data -- the mechanism lives in mcs-prompts, the "
            f"prompts live with their owner."
        ) from exc

    raw_layers: list[tuple[dict, str]] = [(tomllib.loads(raw.decode("utf-8")), where)]

    if override is not None:
        if isinstance(override, (str, Path)):
            with open(override, "rb") as f:
                raw_layers.append((tomllib.load(f), str(override)))
        elif isinstance(override, Mapping):
            data = dict(override)
            if "prompts" not in data:
                data = {"prompts": data}      # a flat mapping is the common case
            raw_layers.append((data, "the override mapping"))
        else:
            raise TypeError(
                f"override must be a path or a mapping, not {type(override).__name__}"
            )

    # Validate NOW, at load -- a broken section must fail where the developer wired it
    # in, not on some later run that happens to hit the matching model.
    layers = [
        _split_table(_table_of(data, where=w), where=w) for data, w in raw_layers
    ]
    return PromptBundle(layers, package=package)
