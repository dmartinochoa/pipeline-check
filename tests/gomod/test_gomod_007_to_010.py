"""Per-rule unit tests for GOMOD-007..010 (Go modules extended pack)."""
from __future__ import annotations

import pathlib

from pipeline_check.core.checks.gomod.base import GoModContext
from pipeline_check.core.checks.gomod.pipelines import GoModChecks


def _scan(tmp_path: pathlib.Path, go_mod: str, has_sum: bool = True):
    (tmp_path / "go.mod").write_text(go_mod, encoding="utf-8")
    if has_sum:
        (tmp_path / "go.sum").write_text("", encoding="utf-8")
    ctx = GoModContext.from_path(str(tmp_path / "go.mod"))
    return {f.check_id: f for f in GoModChecks(ctx).run()}


# ── GOMOD-007 ───────────────────────────────────────────────────


class TestGoMod007VendorModulesStale:
    def test_passes_with_no_vendor_dir(self, tmp_path):
        go_mod = (
            "module example.com/x\ngo 1.22\n"
            "require github.com/foo/bar v1.0.0\n"
        )
        findings = _scan(tmp_path, go_mod)
        assert findings["GOMOD-007"].passed

    def test_fires_when_vendor_dir_without_modules_txt(self, tmp_path):
        (tmp_path / "vendor").mkdir()
        go_mod = (
            "module example.com/x\ngo 1.22\n"
            "require github.com/foo/bar v1.0.0\n"
        )
        findings = _scan(tmp_path, go_mod)
        assert not findings["GOMOD-007"].passed
        assert "missing" in findings["GOMOD-007"].description.lower()

    def test_fires_when_modules_txt_stale(self, tmp_path):
        (tmp_path / "vendor").mkdir()
        (tmp_path / "vendor" / "modules.txt").write_text(
            "# github.com/other/dep v0.5.0\n", encoding="utf-8",
        )
        go_mod = (
            "module example.com/x\ngo 1.22\n"
            "require github.com/foo/bar v1.0.0\n"
        )
        findings = _scan(tmp_path, go_mod)
        assert not findings["GOMOD-007"].passed
        assert "stale" in findings["GOMOD-007"].description.lower()

    def test_passes_when_modules_txt_covers_requires(self, tmp_path):
        (tmp_path / "vendor").mkdir()
        (tmp_path / "vendor" / "modules.txt").write_text(
            "# github.com/foo/bar v1.0.0\n", encoding="utf-8",
        )
        go_mod = (
            "module example.com/x\ngo 1.22\n"
            "require github.com/foo/bar v1.0.0\n"
        )
        findings = _scan(tmp_path, go_mod)
        assert findings["GOMOD-007"].passed


# ── GOMOD-008 ───────────────────────────────────────────────────


class TestGoMod008ReplaceWithoutVersion:
    def test_fires_on_module_to_module_no_version(self, tmp_path):
        go_mod = (
            "module example.com/x\ngo 1.22\n"
            "require github.com/foo/bar v1.0.0\n"
            "replace github.com/foo/bar => github.com/myorg/bar\n"
        )
        findings = _scan(tmp_path, go_mod)
        assert not findings["GOMOD-008"].passed

    def test_passes_when_version_pinned(self, tmp_path):
        go_mod = (
            "module example.com/x\ngo 1.22\n"
            "require github.com/foo/bar v1.0.0\n"
            "replace github.com/foo/bar => github.com/myorg/bar v1.0.1\n"
        )
        findings = _scan(tmp_path, go_mod)
        assert findings["GOMOD-008"].passed

    def test_skips_local_path_replacements(self, tmp_path):
        """Local-path replaces are GOMOD-002's surface."""
        go_mod = (
            "module example.com/x\ngo 1.22\n"
            "require github.com/foo/bar v1.0.0\n"
            "replace github.com/foo/bar => ../local-fork\n"
        )
        findings = _scan(tmp_path, go_mod)
        assert findings["GOMOD-008"].passed


# ── GOMOD-009 ───────────────────────────────────────────────────


class TestGoMod009PrereleaseDirectRequire:
    def test_fires_on_rc_version(self, tmp_path):
        go_mod = (
            "module example.com/x\ngo 1.22\n"
            "require github.com/foo/bar v2.0.0-rc.1\n"
        )
        findings = _scan(tmp_path, go_mod)
        assert not findings["GOMOD-009"].passed

    def test_fires_on_alpha_version(self, tmp_path):
        go_mod = (
            "module example.com/x\ngo 1.22\n"
            "require github.com/foo/bar v3.0.0-alpha\n"
        )
        findings = _scan(tmp_path, go_mod)
        assert not findings["GOMOD-009"].passed

    def test_passes_on_stable_version(self, tmp_path):
        go_mod = (
            "module example.com/x\ngo 1.22\n"
            "require github.com/foo/bar v1.2.3\n"
        )
        findings = _scan(tmp_path, go_mod)
        assert findings["GOMOD-009"].passed

    def test_passes_on_pseudo_version(self, tmp_path):
        # Pseudo-versions (v0.0.0-YYYYMMDDHHMMSS-commit) are excluded;
        # they're Go's canonical commit-pin mechanism.
        go_mod = (
            "module example.com/x\ngo 1.22\n"
            "require github.com/foo/bar v0.0.0-20230101120000-abcdef123456\n"
        )
        findings = _scan(tmp_path, go_mod)
        assert findings["GOMOD-009"].passed

    def test_skips_indirect_requires(self, tmp_path):
        go_mod = (
            "module example.com/x\ngo 1.22\n"
            "require (\n"
            "    github.com/a/b v1.0.0\n"
            "    github.com/c/d v2.0.0-rc.1 // indirect\n"
            ")\n"
        )
        findings = _scan(tmp_path, go_mod)
        assert findings["GOMOD-009"].passed


# ── GOMOD-010 ───────────────────────────────────────────────────


class TestGoMod010ExcludePresent:
    def test_passes_with_no_excludes(self, tmp_path):
        go_mod = (
            "module example.com/x\ngo 1.22\n"
            "require github.com/foo/bar v1.0.0\n"
        )
        findings = _scan(tmp_path, go_mod)
        assert findings["GOMOD-010"].passed

    def test_fires_on_any_exclude(self, tmp_path):
        go_mod = (
            "module example.com/x\ngo 1.22\n"
            "require github.com/foo/bar v1.0.0\n"
            "exclude github.com/old/dep v0.5.0\n"
        )
        findings = _scan(tmp_path, go_mod)
        assert not findings["GOMOD-010"].passed
