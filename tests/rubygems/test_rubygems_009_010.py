"""Per-rule tests for GEM-009 and GEM-010."""
from __future__ import annotations

import pathlib

from pipeline_check.core.checks.rubygems.base import GemContext
from pipeline_check.core.checks.rubygems.pipelines import RubyGemsChecks


def _scan(tmp_path: pathlib.Path) -> dict:
    ctx = GemContext.from_path(str(tmp_path / "Gemfile"))
    return {f.check_id: f for f in RubyGemsChecks(ctx).run()}


def _minimal_gemfile(tmp_path: pathlib.Path) -> None:
    (tmp_path / "Gemfile").write_text(
        "source 'https://rubygems.org'\ngem 'rails', '7.0.4'\n",
        encoding="utf-8",
    )


# ── GEM-009 ────────────────────────────────────────────────


class TestGEM009:
    def test_fires_on_bundle_gems_credential(self, tmp_path):
        _minimal_gemfile(tmp_path)
        (tmp_path / ".bundle").mkdir()
        (tmp_path / ".bundle" / "config").write_text(
            "---\nBUNDLE_GEMS__CORP: bot:s3cr3t\n",
            encoding="utf-8",
        )
        findings = _scan(tmp_path)
        assert not findings["GEM-009"].passed

    def test_fires_on_bundle_github_token(self, tmp_path):
        _minimal_gemfile(tmp_path)
        (tmp_path / ".bundle").mkdir()
        (tmp_path / ".bundle" / "config").write_text(
            "---\nBUNDLE_GITHUB__COM: ghp_xxxxxxx\n",
            encoding="utf-8",
        )
        findings = _scan(tmp_path)
        assert not findings["GEM-009"].passed

    def test_fires_on_password_key(self, tmp_path):
        _minimal_gemfile(tmp_path)
        (tmp_path / ".bundle").mkdir()
        (tmp_path / ".bundle" / "config").write_text(
            "---\nBUNDLE_NEXUS__CORP__PASSWORD: s3cr3t\n",
            encoding="utf-8",
        )
        findings = _scan(tmp_path)
        assert not findings["GEM-009"].passed

    def test_passes_when_no_bundle_config(self, tmp_path):
        _minimal_gemfile(tmp_path)
        findings = _scan(tmp_path)
        assert findings["GEM-009"].passed

    def test_passes_on_config_flags_only(self, tmp_path):
        _minimal_gemfile(tmp_path)
        (tmp_path / ".bundle").mkdir()
        (tmp_path / ".bundle" / "config").write_text(
            "---\nBUNDLE_DEPLOYMENT: \"true\"\n"
            "BUNDLE_FROZEN: \"true\"\n",
            encoding="utf-8",
        )
        findings = _scan(tmp_path)
        assert findings["GEM-009"].passed

    def test_passes_on_env_placeholder(self, tmp_path):
        _minimal_gemfile(tmp_path)
        (tmp_path / ".bundle").mkdir()
        (tmp_path / ".bundle" / "config").write_text(
            "---\nBUNDLE_GEMS__CORP: <%= ENV['NEXUS_TOKEN'] %>\n",
            encoding="utf-8",
        )
        findings = _scan(tmp_path)
        assert findings["GEM-009"].passed


# ── GEM-010 ────────────────────────────────────────────────


class TestGEM010:
    def test_fires_on_dir_glob(self, tmp_path):
        (tmp_path / "Gemfile").write_text(
            "source 'https://rubygems.org'\n"
            "Dir.glob('plugins/*/Gemfile').each { |f| "
            "eval_gemfile f }\n"
            "gem 'rails', '7.0.4'\n",
            encoding="utf-8",
        )
        findings = _scan(tmp_path)
        assert not findings["GEM-010"].passed

    def test_fires_on_require_relative(self, tmp_path):
        (tmp_path / "Gemfile").write_text(
            "source 'https://rubygems.org'\n"
            "require_relative 'gems/internal'\n"
            "gem 'rails', '7.0.4'\n",
            encoding="utf-8",
        )
        findings = _scan(tmp_path)
        assert not findings["GEM-010"].passed

    def test_fires_on_eval(self, tmp_path):
        (tmp_path / "Gemfile").write_text(
            "source 'https://rubygems.org'\n"
            "eval(File.read('extra.gemfile'))\n"
            "gem 'rails', '7.0.4'\n",
            encoding="utf-8",
        )
        findings = _scan(tmp_path)
        assert not findings["GEM-010"].passed

    def test_passes_on_static_eval_gemfile(self, tmp_path):
        # eval_gemfile "literal" is the documented static-include form.
        (tmp_path / "Gemfile").write_text(
            "source 'https://rubygems.org'\n"
            "eval_gemfile 'shared/Gemfile'\n"
            "gem 'rails', '7.0.4'\n",
            encoding="utf-8",
        )
        findings = _scan(tmp_path)
        assert findings["GEM-010"].passed

    def test_passes_on_plain_gemfile(self, tmp_path):
        _minimal_gemfile(tmp_path)
        findings = _scan(tmp_path)
        assert findings["GEM-010"].passed

    def test_passes_on_ruby_version_pin(self, tmp_path):
        # Regression (2026-07 audit, GEM-010): the mainstream Rails idiom
        # ``ruby File.read('.ruby-version').strip`` pins the interpreter
        # version, not a gem list.
        (tmp_path / "Gemfile").write_text(
            "source 'https://rubygems.org'\n"
            "ruby File.read('.ruby-version').strip\n"
            "gem 'rails', '7.0.4'\n",
            encoding="utf-8",
        )
        findings = _scan(tmp_path)
        assert findings["GEM-010"].passed

    def test_still_fires_on_bare_file_read(self, tmp_path):
        # A File.read not in the ``ruby`` version-pin form is still flagged.
        (tmp_path / "Gemfile").write_text(
            "source 'https://rubygems.org'\n"
            "gems = File.read('gemlist.txt')\n"
            "gem 'rails', '7.0.4'\n",
            encoding="utf-8",
        )
        findings = _scan(tmp_path)
        assert not findings["GEM-010"].passed

    def test_skips_constructs_in_comments(self, tmp_path):
        (tmp_path / "Gemfile").write_text(
            "source 'https://rubygems.org'\n"
            "# Dir.glob('plugins/*/Gemfile').each { |f| "
            "eval_gemfile f }\n"
            "gem 'rails', '7.0.4'\n",
            encoding="utf-8",
        )
        findings = _scan(tmp_path)
        assert findings["GEM-010"].passed
