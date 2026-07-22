"""Regression tests from the 2026-07 rule audit (RubyGems LOW findings)."""
from __future__ import annotations

import pathlib

from pipeline_check.core.checks.rubygems.base import GemContext
from pipeline_check.core.checks.rubygems.pipelines import RubyGemsChecks


def _scan(tmp_path: pathlib.Path, gemfile: str) -> dict:
    (tmp_path / "Gemfile").write_text(gemfile, encoding="utf-8")
    ctx = GemContext.from_path(str(tmp_path / "Gemfile"))
    return {f.check_id: f for f in RubyGemsChecks(ctx).run()}


class TestAudit202607LowRubyGemsC1:
    def test_gem007_two_public_rubygems_sources_pass(self, tmp_path):
        # Two identical public rubygems.org sources are redundant, not a
        # dependency-confusion split.
        findings = _scan(
            tmp_path,
            "source 'https://rubygems.org'\n"
            "source 'https://rubygems.org'\n"
            "gem 'rails', '7.0.4'\n",
        )
        assert findings["GEM-007"].passed is True

    def test_gem007_public_plus_private_source_fires(self, tmp_path):
        findings = _scan(
            tmp_path,
            "source 'https://rubygems.org'\n"
            "source 'https://gems.corp/private'\n"
            "gem 'internal-tool', '1.0.0'\n",
        )
        assert findings["GEM-007"].passed is False

    def test_gem010_load_directive_fires(self, tmp_path):
        # ``load "extra.rb"`` executes a file that may add gem
        # declarations; docs_note already claimed it was matched.
        findings = _scan(
            tmp_path,
            "source 'https://rubygems.org'\n"
            "load 'extra_gems.rb'\n"
            "gem 'rails', '7.0.4'\n",
        )
        assert findings["GEM-010"].passed is False

    def test_gem010_plain_require_still_passes(self, tmp_path):
        # A bare ``require`` merely loads a library and must not fire.
        findings = _scan(
            tmp_path,
            "source 'https://rubygems.org'\n"
            "require 'json'\n"
            "gem 'rails', '7.0.4'\n",
        )
        assert findings["GEM-010"].passed is True
