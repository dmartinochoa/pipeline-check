"""Go modules rule pack: per-rule pass / fail / edge-case tests."""
from __future__ import annotations

import pathlib

import pytest

from pipeline_check.core.checks.gomod.base import GoModContext
from pipeline_check.core.checks.gomod.pipelines import GoModChecks


def _scan(tmp_path: pathlib.Path, go_mod: str, has_sum: bool = False):
    """Write go.mod (and optionally go.sum) under tmp_path, return
    ``{check_id: Finding}`` from a full provider scan."""
    (tmp_path / "go.mod").write_text(go_mod, encoding="utf-8")
    if has_sum:
        (tmp_path / "go.sum").write_text("", encoding="utf-8")
    ctx = GoModContext.from_path(str(tmp_path / "go.mod"))
    findings = GoModChecks(ctx).run()
    return {f.check_id: f for f in findings}


# ── Parser sanity ────────────────────────────────────────────────


class TestParser:
    def test_parses_require_block_with_indirect_marker(self, tmp_path):
        go_mod = (
            "module example.com/x\n"
            "go 1.22\n"
            "require (\n"
            "    github.com/a/b v1.0.0\n"
            "    github.com/c/d v2.0.0 // indirect\n"
            ")\n"
        )
        findings = _scan(tmp_path, go_mod, has_sum=True)
        ctx = GoModContext.from_path(str(tmp_path / "go.mod"))
        pom = ctx.files[0]
        assert pom.module_path == "example.com/x"
        assert pom.go_version == "1.22"
        assert [r.path for r in pom.requires] == [
            "github.com/a/b", "github.com/c/d",
        ]
        assert pom.requires[0].indirect is False
        assert pom.requires[1].indirect is True

    def test_parses_single_line_require(self, tmp_path):
        go_mod = (
            "module example.com/x\n"
            "go 1.22\n"
            "require github.com/foo/bar v1.0.0\n"
        )
        (tmp_path / "go.mod").write_text(go_mod, encoding="utf-8")
        ctx = GoModContext.from_path(str(tmp_path / "go.mod"))
        assert len(ctx.files[0].requires) == 1


# ── GOMOD-001 ──────────────────────────────────────────────────


class TestGoMod001:
    def test_fires_when_go_sum_missing(self, tmp_path):
        go_mod = (
            "module example.com/x\n"
            "go 1.22\n"
            "require github.com/foo/bar v1.0.0\n"
        )
        findings = _scan(tmp_path, go_mod, has_sum=False)
        assert not findings["GOMOD-001"].passed

    def test_passes_when_go_sum_present(self, tmp_path):
        go_mod = (
            "module example.com/x\n"
            "go 1.22\n"
            "require github.com/foo/bar v1.0.0\n"
        )
        findings = _scan(tmp_path, go_mod, has_sum=True)
        assert findings["GOMOD-001"].passed

    def test_passes_when_no_requires(self, tmp_path):
        """Empty require block => absent go.sum is a no-op."""
        go_mod = "module example.com/x\ngo 1.22\n"
        findings = _scan(tmp_path, go_mod, has_sum=False)
        assert findings["GOMOD-001"].passed


# ── GOMOD-002 ──────────────────────────────────────────────────


class TestGoMod002:
    def test_fires_on_relative_path_replace(self, tmp_path):
        go_mod = (
            "module example.com/x\n"
            "go 1.22\n"
            "require github.com/foo/bar v1.0.0\n"
            "replace github.com/foo/bar => ../local-fork\n"
        )
        findings = _scan(tmp_path, go_mod, has_sum=True)
        assert not findings["GOMOD-002"].passed

    def test_passes_on_module_to_module_replace(self, tmp_path):
        go_mod = (
            "module example.com/x\n"
            "go 1.22\n"
            "require github.com/foo/bar v1.0.0\n"
            "replace github.com/foo/bar => github.com/myorg/bar v1.0.1\n"
        )
        findings = _scan(tmp_path, go_mod, has_sum=True)
        # GOMOD-002 only fires on local-path; GOMOD-003 owns the
        # module-to-module case.
        assert findings["GOMOD-002"].passed
        assert not findings["GOMOD-003"].passed

    def test_passes_when_no_replace(self, tmp_path):
        go_mod = "module example.com/x\ngo 1.22\n"
        findings = _scan(tmp_path, go_mod, has_sum=True)
        assert findings["GOMOD-002"].passed


# ── GOMOD-003 ──────────────────────────────────────────────────


class TestGoMod003:
    def test_passes_on_same_module_version_pin(self, tmp_path):
        go_mod = (
            "module example.com/x\n"
            "go 1.22\n"
            "require github.com/foo/bar v1.0.0\n"
            "replace github.com/foo/bar => github.com/foo/bar v1.0.1\n"
        )
        findings = _scan(tmp_path, go_mod, has_sum=True)
        assert findings["GOMOD-003"].passed

    def test_fires_on_cross_module_replace(self, tmp_path):
        go_mod = (
            "module example.com/x\n"
            "go 1.22\n"
            "require github.com/popular/lib v1.2.3\n"
            "replace github.com/popular/lib => github.com/attacker/fork v1.2.3\n"
        )
        findings = _scan(tmp_path, go_mod, has_sum=True)
        assert not findings["GOMOD-003"].passed


# ── GOMOD-004 ──────────────────────────────────────────────────


class TestGoMod004:
    def test_fires_on_direct_incompatible_require(self, tmp_path):
        go_mod = (
            "module example.com/x\n"
            "go 1.22\n"
            "require github.com/legacy/lib v3.0.0+incompatible\n"
        )
        findings = _scan(tmp_path, go_mod, has_sum=True)
        assert not findings["GOMOD-004"].passed

    def test_passes_when_only_indirect_incompatible(self, tmp_path):
        """Indirect requires are exempt from GOMOD-004."""
        go_mod = (
            "module example.com/x\n"
            "go 1.22\n"
            "require (\n"
            "    github.com/foo/bar v1.0.0\n"
            "    github.com/legacy/lib v3.0.0+incompatible // indirect\n"
            ")\n"
        )
        findings = _scan(tmp_path, go_mod, has_sum=True)
        assert findings["GOMOD-004"].passed


# ── GOMOD-005 ──────────────────────────────────────────────────


class TestGoMod005:
    def test_fires_when_go_directive_absent(self, tmp_path):
        go_mod = (
            "module example.com/x\n"
            "require github.com/foo/bar v1.0.0\n"
        )
        findings = _scan(tmp_path, go_mod, has_sum=True)
        assert not findings["GOMOD-005"].passed

    def test_passes_when_go_directive_present(self, tmp_path):
        go_mod = (
            "module example.com/x\n"
            "go 1.22\n"
            "require github.com/foo/bar v1.0.0\n"
        )
        findings = _scan(tmp_path, go_mod, has_sum=True)
        assert findings["GOMOD-005"].passed


# ── GOMOD-006 ──────────────────────────────────────────────────


class TestGoMod006:
    def test_passes_with_no_match(self, tmp_path):
        go_mod = (
            "module example.com/x\n"
            "go 1.22\n"
            "require github.com/foo/bar v1.0.0\n"
        )
        findings = _scan(tmp_path, go_mod, has_sum=True)
        assert findings["GOMOD-006"].passed

    def test_fires_on_compromised_entry(self, tmp_path):
        # The seeded synthetic entry; assertion uses the in-file
        # value to stay robust against future registry edits.
        from pipeline_check.core.checks.gomod._compromised_modules import (
            COMPROMISED,
        )
        seed = COMPROMISED[1]
        go_mod = (
            "module example.com/x\n"
            "go 1.22\n"
            f"require {seed.module_path} {seed.malicious_versions[0]}\n"
        )
        findings = _scan(tmp_path, go_mod, has_sum=True)
        assert not findings["GOMOD-006"].passed


# ── End-to-end provider routing ────────────────────────────────


def test_provider_in_registry():
    from pipeline_check.core.providers import available
    assert "gomod" in available()


def test_provider_raises_without_path():
    from pipeline_check.core.providers import get
    prov = get("gomod")
    with pytest.raises(ValueError, match="gomod-path"):
        prov.build_context()
