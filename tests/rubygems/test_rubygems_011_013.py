"""Per-rule tests for GEM-011..013 (RubyGems supply-chain pack)."""
from __future__ import annotations

import pathlib

from pipeline_check.core.checks.rubygems.base import GemContext
from pipeline_check.core.checks.rubygems.pipelines import RubyGemsChecks


def _scan(tmp_path: pathlib.Path, gemfile: str) -> dict:
    (tmp_path / "Gemfile").write_text(gemfile, encoding="utf-8")
    ctx = GemContext.from_path(str(tmp_path / "Gemfile"))
    return {f.check_id: f for f in RubyGemsChecks(ctx).run()}


_BASE = "source 'https://rubygems.org'\ngem 'rails', '7.0.4'\n"


# ── GEM-011 (Bundler plugin) ────────────────────────────────


class TestGEM011BundlerPlugin:
    def test_passes_with_no_plugin(self, tmp_path):
        findings = _scan(tmp_path, _BASE)
        assert findings["GEM-011"].passed

    def test_fires_on_plugin_directive(self, tmp_path):
        gemfile = (
            "source 'https://rubygems.org'\n"
            "plugin 'some-bundler-plugin'\n"
            "gem 'rails', '7.0.4'\n"
        )
        findings = _scan(tmp_path, gemfile)
        assert not findings["GEM-011"].passed
        assert "some-bundler-plugin" in findings["GEM-011"].description

    def test_skips_plugin_in_comment(self, tmp_path):
        gemfile = (
            "source 'https://rubygems.org'\n"
            "# plugin 'commented-out'\n"
            "gem 'rails', '7.0.4'\n"
        )
        findings = _scan(tmp_path, gemfile)
        assert findings["GEM-011"].passed

    def test_does_not_fire_on_plain_gem(self, tmp_path):
        # A gem whose name contains "plugin" must not match.
        gemfile = (
            "source 'https://rubygems.org'\n"
            "gem 'some-plugin-gem', '1.0.0'\n"
        )
        findings = _scan(tmp_path, gemfile)
        assert findings["GEM-011"].passed


# ── GEM-012 (per-gem :source) ───────────────────────────────


class TestGEM012PerGemSource:
    def test_passes_with_no_per_gem_source(self, tmp_path):
        findings = _scan(tmp_path, _BASE)
        assert findings["GEM-012"].passed

    def test_fires_on_inline_source_option(self, tmp_path):
        gemfile = (
            "source 'https://rubygems.org'\n"
            "gem 'rails', '7.0.4'\n"
            "gem 'internal-helper', source: 'https://gems.internal'\n"
        )
        findings = _scan(tmp_path, gemfile)
        assert not findings["GEM-012"].passed
        assert "internal-helper" in findings["GEM-012"].description

    def test_scoped_source_block_does_not_trip_per_gem(self, tmp_path):
        # A scoped ``source ... do`` block is GEM-007's surface, not
        # an inline per-gem ``source:`` option.
        gemfile = (
            "source 'https://rubygems.org'\n"
            "source 'https://gems.internal' do\n"
            "  gem 'internal-helper'\n"
            "end\n"
        )
        findings = _scan(tmp_path, gemfile)
        assert findings["GEM-012"].passed


# ── GEM-013 (insecure git transport) ────────────────────────


class TestGEM013GitInsecureTransport:
    def test_passes_on_https_git(self, tmp_path):
        gemfile = (
            "source 'https://rubygems.org'\n"
            "gem 'x', git: 'https://example.com/org/x', ref: 'abc123'\n"
        )
        findings = _scan(tmp_path, gemfile)
        assert findings["GEM-013"].passed

    def test_passes_on_github_shorthand(self, tmp_path):
        gemfile = (
            "source 'https://rubygems.org'\n"
            "gem 'x', github: 'org/x', ref: 'abc123'\n"
        )
        findings = _scan(tmp_path, gemfile)
        assert findings["GEM-013"].passed

    def test_fires_on_git_protocol(self, tmp_path):
        gemfile = (
            "source 'https://rubygems.org'\n"
            "gem 'x', git: 'git://example.com/org/x'\n"
        )
        findings = _scan(tmp_path, gemfile)
        assert not findings["GEM-013"].passed

    def test_fires_on_http_git_url(self, tmp_path):
        gemfile = (
            "source 'https://rubygems.org'\n"
            "gem 'x', git: 'http://internal/repos/x', ref: 'abc123'\n"
        )
        findings = _scan(tmp_path, gemfile)
        assert not findings["GEM-013"].passed
