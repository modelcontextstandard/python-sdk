"""Tests for StaticProvider."""

from __future__ import annotations

import os

import pytest

from mcs.auth.provider import CredentialProvider
from mcs.auth.static import StaticProvider


class TestStaticProvider:

    def test_satisfies_protocol(self):
        provider = StaticProvider({"gmail": "tok123"})
        assert isinstance(provider, CredentialProvider)

    def test_get_token_from_dict(self):
        provider = StaticProvider({"gmail": "tok-gmail", "slack": "tok-slack"})
        assert provider.get_token("gmail") == "tok-gmail"
        assert provider.get_token("slack") == "tok-slack"

    def test_get_token_from_env(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("MCS_TOKEN_GITHUB", "tok-gh")
        provider = StaticProvider()
        assert provider.get_token("github") == "tok-gh"

    def test_get_token_env_normalisation(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("MCS_TOKEN_MY_API", "tok-api")
        provider = StaticProvider()
        assert provider.get_token("my-api") == "tok-api"

    def test_dict_takes_precedence_over_env(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("MCS_TOKEN_GMAIL", "env-token")
        provider = StaticProvider({"gmail": "dict-token"})
        assert provider.get_token("gmail") == "dict-token"

    def test_missing_scope_raises_lookup_error(self):
        provider = StaticProvider()
        with pytest.raises(LookupError, match="No credential for scope 'unknown'"):
            provider.get_token("unknown")

    def test_empty_provider(self):
        provider = StaticProvider()
        with pytest.raises(LookupError):
            provider.get_token("anything")
