"""The loader against a fixture package -- defaults, variants, overrides, precedence."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))   # makes `fixturepkg` importable

from mcs.prompts import PromptBundle, PromptSet, load_prompts


class TestDefaults:

    def test_loads_the_package_base(self):
        p = load_prompts("fixturepkg").resolve()
        assert p["greet"] == "Hello, {name}."
        assert p["farewell"] == "Bye, {name}."

    def test_missing_defaults_name_the_convention(self):
        """The error teaches the rule: prompts live with their owner."""
        with pytest.raises(FileNotFoundError, match="live with their owner"):
            load_prompts("fixturepkg", "prompts/nope.toml")

    def test_a_missing_prompt_lists_what_exists(self):
        with pytest.raises(KeyError, match="farewell"):
            load_prompts("fixturepkg").resolve()["does_not_exist"]

    def test_mapping_behaviour(self):
        p = load_prompts("fixturepkg").resolve()
        assert isinstance(p, PromptSet)
        assert "greet" in p and len(p) == 2
        assert p.get("does_not_exist") is None


class TestModelVariants:

    def test_no_model_means_base_only(self):
        assert load_prompts("fixturepkg").resolve()["greet"] == "Hello, {name}."

    def test_a_matching_pattern_applies(self):
        p = load_prompts("fixturepkg").resolve(model="qwen2:7b")
        assert p["greet"] == "QWEN says hello to {name}."
        assert p["farewell"] == "Bye, {name}."          # untouched: variants are sparse

    def test_later_matching_sections_win(self):
        """qwen3:4b matches both ``qwen*`` and the exact section -- file order decides,
        so the more specific section is written later and wins."""
        p = load_prompts("fixturepkg").resolve(model="qwen3:4b")
        assert p["greet"] == "Exactly qwen3:4b greets {name}."

    def test_a_non_matching_model_stays_on_base(self):
        assert load_prompts("fixturepkg").resolve(model="gpt-5.6")["greet"] == "Hello, {name}."


class TestLateResolution:
    """Loading and resolving are separate because the model can change between calls
    -- an agent switches, a router falls back. One bundle, many resolutions."""

    def test_one_bundle_serves_many_models(self):
        bundle = load_prompts("fixturepkg")
        assert isinstance(bundle, PromptBundle)
        assert bundle.resolve(model="qwen2:7b")["greet"] == "QWEN says hello to {name}."
        assert bundle.resolve(model="gpt-5.6")["greet"] == "Hello, {name}."
        assert bundle.resolve()["greet"] == "Hello, {name}."

    def test_resolution_is_cached_per_id(self):
        bundle = load_prompts("fixturepkg")
        assert bundle.resolve(model="qwen2:7b") is bundle.resolve(model="qwen2:7b")
        assert bundle.resolve() is bundle.resolve()

    def test_broken_overrides_fail_at_load_not_at_resolve(self, tmp_path):
        """Where the developer wired it in -- not on some later run that happens to
        hit the matching model."""
        f = tmp_path / "broken.toml"
        f.write_text('[prompts."model:qwen*"]\ngreet = 42\n', encoding="utf-8")
        with pytest.raises(ValueError):
            load_prompts("fixturepkg", override=f)


class TestOverrides:

    def test_a_flat_mapping_overrides_sparsely(self):
        p = load_prompts("fixturepkg", override={"greet": "Custom {name}!"}).resolve()
        assert p["greet"] == "Custom {name}!"
        assert p["farewell"] == "Bye, {name}."

    def test_an_override_file_with_model_sections(self, tmp_path):
        f = tmp_path / "mine.toml"
        f.write_text(
            '[prompts]\ngreet = "File base {name}."\n\n'
            '[prompts."model:gpt*"]\ngreet = "File gpt {name}."\n',
            encoding="utf-8",
        )
        assert load_prompts("fixturepkg", override=f).resolve()["greet"] == "File base {name}."
        assert load_prompts("fixturepkg", override=f).resolve(model="gpt-5.6")["greet"] == "File gpt {name}."

    def test_the_override_base_beats_a_package_variant(self):
        """Precedence weakest to strongest: package base -> package variants ->
        override base -> override variants. The developer's word beats shipped
        tuning."""
        p = load_prompts("fixturepkg", override={"greet": "Mine."}).resolve(model="qwen3:4b")
        assert p["greet"] == "Mine."

    def test_junk_in_the_table_fails_loudly(self, tmp_path):
        f = tmp_path / "broken.toml"
        f.write_text('[prompts]\ngreet = 42\n', encoding="utf-8")
        with pytest.raises(ValueError, match="Unexpected entry"):
            load_prompts("fixturepkg", override=f)

    def test_a_file_without_prompts_table_fails_loudly(self, tmp_path):
        f = tmp_path / "empty.toml"
        f.write_text('[other]\nx = "y"\n', encoding="utf-8")
        with pytest.raises(ValueError, match=r"no \[prompts\] table"):
            load_prompts("fixturepkg", override=f)
