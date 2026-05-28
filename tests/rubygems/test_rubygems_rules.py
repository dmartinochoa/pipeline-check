"""RubyGems / Bundler rule pack: per-rule pass / fail / edge-case tests."""
from __future__ import annotations

import pathlib

from pipeline_check.core.checks.rubygems.base import GemContext
from pipeline_check.core.checks.rubygems.pipelines import RubyGemsChecks


def _scan(
    tmp_path: pathlib.Path,
    gemfile: str,
    has_lock: bool = False,
) -> dict:
    (tmp_path / "Gemfile").write_text(gemfile, encoding="utf-8")
    if has_lock:
        (tmp_path / "Gemfile.lock").write_text("", encoding="utf-8")
    ctx = GemContext.from_path(str(tmp_path / "Gemfile"))
    findings = RubyGemsChecks(ctx).run()
    return {f.check_id: f for f in findings}


# ── Parser sanity ─────────────────────────────────────────────


class TestParser:
    def test_parses_short_and_long_gem_forms(self, tmp_path):
        gemfile = (
            "source 'https://rubygems.org'\n"
            "\n"
            "gem 'rails', '7.0.4'\n"
            "gem 'puma'\n"
            "gem 'pg', '~> 1.5'\n"
            "gem 'some_gem', git: 'https://github.com/x/y', "
            "ref: 'abc123'\n"
            "gem 'gh_gem', github: 'owner/repo'\n"
            "gem 'local_gem', path: '../local'\n"
        )
        (tmp_path / "Gemfile").write_text(gemfile)
        ctx = GemContext.from_path(str(tmp_path / "Gemfile"))
        deps = {d.name: d for d in ctx.files[0].dependencies}
        assert deps["rails"].version == "7.0.4"
        assert deps["puma"].version is None
        assert deps["pg"].version == "~> 1.5"
        assert deps["some_gem"].is_git
        assert deps["some_gem"].git_ref == "abc123"
        assert not deps["some_gem"].git_mutable
        assert deps["gh_gem"].is_git
        assert deps["gh_gem"].git_mutable
        assert deps["local_gem"].is_path

    def test_parses_groups_and_scoped_sources(self, tmp_path):
        gemfile = (
            "source 'https://rubygems.org'\n"
            "\n"
            "group :development do\n"
            "  gem 'rspec', '3.12.0'\n"
            "end\n"
            "\n"
            "source 'https://gems.corp/private' do\n"
            "  gem 'internal-tool', '1.0.0'\n"
            "end\n"
        )
        (tmp_path / "Gemfile").write_text(gemfile)
        ctx = GemContext.from_path(str(tmp_path / "Gemfile"))
        deps = {d.name: d for d in ctx.files[0].dependencies}
        assert deps["rspec"].groups == ("development",)
        assert deps["internal-tool"].scoped_source == (
            "https://gems.corp/private"
        )

    def test_recognizes_top_level_vs_block_sources(self, tmp_path):
        gemfile = (
            "source 'https://rubygems.org'\n"
            "source 'https://gems.corp/private' do\n"
            "  gem 'internal', '1.0.0'\n"
            "end\n"
        )
        (tmp_path / "Gemfile").write_text(gemfile)
        ctx = GemContext.from_path(str(tmp_path / "Gemfile"))
        top_level = [s for s in ctx.files[0].sources if s.is_top_level]
        assert len(top_level) == 1
        assert top_level[0].url == "https://rubygems.org"


# ── GEM-001 ────────────────────────────────────────────────


class TestGEM001:
    def test_passes_with_lockfile(self, tmp_path):
        findings = _scan(
            tmp_path,
            "source 'https://rubygems.org'\ngem 'rails', '7.0.4'\n",
            has_lock=True,
        )
        assert findings["GEM-001"].passed

    def test_fails_without_lockfile(self, tmp_path):
        findings = _scan(
            tmp_path,
            "source 'https://rubygems.org'\ngem 'rails', '7.0.4'\n",
        )
        assert not findings["GEM-001"].passed

    def test_passes_when_no_deps(self, tmp_path):
        findings = _scan(tmp_path, "source 'https://rubygems.org'\n")
        assert findings["GEM-001"].passed


# ── GEM-002 ────────────────────────────────────────────────


class TestGEM002:
    def test_fires_on_tilde_arrow(self, tmp_path):
        findings = _scan(
            tmp_path,
            "source 'https://rubygems.org'\ngem 'rails', '~> 7.0'\n",
        )
        assert not findings["GEM-002"].passed

    def test_fires_on_no_version(self, tmp_path):
        findings = _scan(
            tmp_path,
            "source 'https://rubygems.org'\ngem 'rails'\n",
        )
        assert not findings["GEM-002"].passed

    def test_fires_on_gte(self, tmp_path):
        findings = _scan(
            tmp_path,
            "source 'https://rubygems.org'\ngem 'rails', '>= 7.0'\n",
        )
        assert not findings["GEM-002"].passed

    def test_passes_on_exact_pin(self, tmp_path):
        findings = _scan(
            tmp_path,
            "source 'https://rubygems.org'\ngem 'rails', '7.0.4'\n",
        )
        assert findings["GEM-002"].passed

    def test_skips_git_entry(self, tmp_path):
        findings = _scan(
            tmp_path,
            "source 'https://rubygems.org'\n"
            "gem 'x', github: 'owner/x', ref: 'abc'\n",
        )
        assert findings["GEM-002"].passed

    def test_fires_on_range(self, tmp_path):
        findings = _scan(
            tmp_path,
            "source 'https://rubygems.org'\n"
            "gem 'rails', '>= 7.0', '< 8'\n",
        )
        assert not findings["GEM-002"].passed


# ── GEM-003 ────────────────────────────────────────────────


class TestGEM003:
    def test_fires_on_http_source(self, tmp_path):
        findings = _scan(
            tmp_path,
            "source 'http://internal/gems'\ngem 'rails', '7.0.4'\n",
        )
        assert not findings["GEM-003"].passed

    def test_passes_on_https_source(self, tmp_path):
        findings = _scan(
            tmp_path,
            "source 'https://rubygems.org'\ngem 'rails', '7.0.4'\n",
        )
        assert findings["GEM-003"].passed


# ── GEM-004 ────────────────────────────────────────────────


class TestGEM004:
    def test_fires_on_embedded_credentials(self, tmp_path):
        findings = _scan(
            tmp_path,
            "source 'https://bot:s3cr3t@gems.corp/private'\n"
            "gem 'internal', '1.0.0'\n",
        )
        assert not findings["GEM-004"].passed
        assert "s3cr3t" not in findings["GEM-004"].description

    def test_passes_on_clean_url(self, tmp_path):
        findings = _scan(
            tmp_path,
            "source 'https://gems.corp/private'\n"
            "gem 'internal', '1.0.0'\n",
        )
        assert findings["GEM-004"].passed

    def test_skips_env_placeholder(self, tmp_path):
        # ``$BUNDLE_TOKEN`` is a shell-expansion placeholder, not a
        # literal credential.
        findings = _scan(
            tmp_path,
            "source 'https://bot:$BUNDLE_TOKEN@gems.corp/private'\n"
            "gem 'internal', '1.0.0'\n",
        )
        assert findings["GEM-004"].passed


# ── GEM-005 ────────────────────────────────────────────────


class TestGEM005:
    def test_fires_on_branch_pin(self, tmp_path):
        findings = _scan(
            tmp_path,
            "source 'https://rubygems.org'\n"
            "gem 'x', git: 'https://github.com/x/y', branch: 'main'\n",
        )
        assert not findings["GEM-005"].passed

    def test_fires_on_github_no_ref(self, tmp_path):
        findings = _scan(
            tmp_path,
            "source 'https://rubygems.org'\n"
            "gem 'x', github: 'owner/repo'\n",
        )
        assert not findings["GEM-005"].passed

    def test_passes_on_ref_sha(self, tmp_path):
        findings = _scan(
            tmp_path,
            "source 'https://rubygems.org'\n"
            "gem 'x', git: 'https://github.com/x/y', "
            "ref: 'a1b2c3d4'\n",
        )
        assert findings["GEM-005"].passed

    def test_passes_when_no_git_entries(self, tmp_path):
        findings = _scan(
            tmp_path,
            "source 'https://rubygems.org'\ngem 'rails', '7.0.4'\n",
        )
        assert findings["GEM-005"].passed


# ── GEM-006 ────────────────────────────────────────────────


class TestGEM006:
    def test_fires_on_rest_client_cve(self, tmp_path):
        findings = _scan(
            tmp_path,
            "source 'https://rubygems.org'\n"
            "gem 'rest-client', '1.6.13'\n",
        )
        assert not findings["GEM-006"].passed
        assert "CVE-2019-15224" in findings["GEM-006"].description

    def test_fires_on_strong_password_cve(self, tmp_path):
        findings = _scan(
            tmp_path,
            "source 'https://rubygems.org'\n"
            "gem 'strong_password', '0.0.7'\n",
        )
        assert not findings["GEM-006"].passed

    def test_passes_on_clean_pin(self, tmp_path):
        findings = _scan(
            tmp_path,
            "source 'https://rubygems.org'\n"
            "gem 'rest-client', '2.1.0'\n",
        )
        assert findings["GEM-006"].passed

    def test_strips_equals_prefix(self, tmp_path):
        # Bundler allows ``"= 1.6.13"`` as an exact pin form.
        findings = _scan(
            tmp_path,
            "source 'https://rubygems.org'\n"
            "gem 'rest-client', '= 1.6.13'\n",
        )
        assert not findings["GEM-006"].passed


# ── GEM-007 ────────────────────────────────────────────────


class TestGEM007:
    def test_fires_on_two_top_level_sources(self, tmp_path):
        findings = _scan(
            tmp_path,
            "source 'https://rubygems.org'\n"
            "source 'https://gems.corp/private'\n"
            "gem 'internal-tool', '1.0.0'\n",
        )
        assert not findings["GEM-007"].passed

    def test_passes_with_scoped_block(self, tmp_path):
        findings = _scan(
            tmp_path,
            "source 'https://rubygems.org'\n"
            "source 'https://gems.corp/private' do\n"
            "  gem 'internal-tool', '1.0.0'\n"
            "end\n",
        )
        assert findings["GEM-007"].passed

    def test_passes_with_single_source(self, tmp_path):
        findings = _scan(
            tmp_path,
            "source 'https://rubygems.org'\n"
            "gem 'rails', '7.0.4'\n",
        )
        assert findings["GEM-007"].passed


# ── GEM-008 ────────────────────────────────────────────────


class TestGEM008:
    def test_fires_on_top_level_path(self, tmp_path):
        findings = _scan(
            tmp_path,
            "source 'https://rubygems.org'\n"
            "gem 'internal-helper', path: '../internal-helper'\n",
        )
        assert not findings["GEM-008"].passed

    def test_passes_on_dev_only_path(self, tmp_path):
        findings = _scan(
            tmp_path,
            "source 'https://rubygems.org'\n"
            "group :development do\n"
            "  gem 'internal-helper', path: '../internal-helper'\n"
            "end\n",
        )
        assert findings["GEM-008"].passed

    def test_passes_on_test_only_path(self, tmp_path):
        findings = _scan(
            tmp_path,
            "source 'https://rubygems.org'\n"
            "group :test do\n"
            "  gem 'fixture-helper', path: 'spec/fixtures'\n"
            "end\n",
        )
        assert findings["GEM-008"].passed

    def test_passes_without_path_entries(self, tmp_path):
        findings = _scan(
            tmp_path,
            "source 'https://rubygems.org'\n"
            "gem 'rails', '7.0.4'\n",
        )
        assert findings["GEM-008"].passed
