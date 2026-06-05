"""Tests for NPM-019 (overrides / resolutions redirect to a non-registry source)."""
from __future__ import annotations

from .conftest import run_check_manifest


class TestNPM019OverrideRedirect:
    def test_fails_on_npm_alias_override(self):
        f = run_check_manifest(
            {"overrides": {"chalk": "npm:chalk-evil@5.0.0"}}, "NPM-019",
        )
        assert not f.passed
        assert "chalk" in f.description

    def test_fails_on_git_override(self):
        f = run_check_manifest(
            {"overrides": {"ansi-styles": "git+https://github.com/x/y.git#main"}},
            "NPM-019",
        )
        assert not f.passed

    def test_fails_on_nested_override_with_url(self):
        f = run_check_manifest(
            {"overrides": {"foo": {"bar": "https://evil.test/bar.tgz"}}},
            "NPM-019",
        )
        assert not f.passed

    def test_fails_on_yarn_resolutions_file_path(self):
        f = run_check_manifest(
            {"resolutions": {"**/lodash": "file:../evil"}}, "NPM-019",
        )
        assert not f.passed

    def test_fails_on_pnpm_overrides_github_shorthand(self):
        f = run_check_manifest(
            {"pnpm": {"overrides": {"left-pad": "github:attacker/left-pad"}}},
            "NPM-019",
        )
        assert not f.passed

    def test_passes_on_plain_version_override(self):
        f = run_check_manifest(
            {"overrides": {"ansi-styles": "6.2.1"}}, "NPM-019",
        )
        assert f.passed

    def test_passes_when_no_overrides(self):
        f = run_check_manifest(
            {"dependencies": {"x": "^1.0.0"}}, "NPM-019",
        )
        assert f.passed
