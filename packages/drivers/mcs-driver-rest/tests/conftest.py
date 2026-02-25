"""Shared fixtures for RestToolDriver tests."""

from __future__ import annotations

import json
import pathlib
from typing import Any, Dict

import pytest

FIXTURES_DIR = pathlib.Path(__file__).parent / "fixtures"
OPENAPI3_DIR = FIXTURES_DIR / "openapi3"
SWAGGER2_DIR = FIXTURES_DIR / "swagger2"


def _load_spec(path: pathlib.Path) -> Dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix in (".yaml", ".yml"):
        import yaml
        return yaml.safe_load(text)
    return json.loads(text)


def _collect_fixture_files(*dirs: pathlib.Path) -> list[pathlib.Path]:
    files = []
    for d in dirs:
        if d.exists():
            files.extend(sorted(d.glob("*")))
    return files


ALL_FIXTURES = _collect_fixture_files(OPENAPI3_DIR, SWAGGER2_DIR)
OPENAPI3_FIXTURES = _collect_fixture_files(OPENAPI3_DIR)
SWAGGER2_FIXTURES = _collect_fixture_files(SWAGGER2_DIR)


@pytest.fixture(params=ALL_FIXTURES, ids=lambda p: p.name)
def spec_file(request: pytest.FixtureRequest) -> pathlib.Path:
    return request.param


@pytest.fixture(params=OPENAPI3_FIXTURES, ids=lambda p: p.name)
def openapi3_file(request: pytest.FixtureRequest) -> pathlib.Path:
    return request.param


@pytest.fixture(params=SWAGGER2_FIXTURES, ids=lambda p: p.name)
def swagger2_file(request: pytest.FixtureRequest) -> pathlib.Path:
    return request.param


@pytest.fixture()
def load_spec():
    """Return a callable that loads and parses a spec file."""
    return _load_spec
