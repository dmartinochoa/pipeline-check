"""Cargo rule pack: per-rule pass / fail / edge-case tests."""
from __future__ import annotations

import pathlib

import pytest

from pipeline_check.core.checks.cargo.base import CargoContext
from pipeline_check.core.checks.cargo.pipelines import CargoChecks


def _scan(
    tmp_path: pathlib.Path, cargo_toml: str,
    has_lock: bool = False,
    workspace_root_with_lock: bool = False,
):
    """Write Cargo.toml under tmp_path (and optionally Cargo.lock),
    return ``{check_id: Finding}`` from a full provider scan."""
    (tmp_path / "Cargo.toml").write_text(cargo_toml, encoding="utf-8")
    if has_lock:
        (tmp_path / "Cargo.lock").write_text("", encoding="utf-8")
    if workspace_root_with_lock:
        (tmp_path.parent / "Cargo.lock").write_text(
            "", encoding="utf-8",
        )
    ctx = CargoContext.from_path(str(tmp_path / "Cargo.toml"))
    findings = CargoChecks(ctx).run()
    return {f.check_id: f for f in findings}


# ── Parser sanity ─────────────────────────────────────────────


class TestParser:
    def test_parses_short_and_long_dep_forms(self, tmp_path):
        cargo_toml = (
            '[package]\n'
            'name = "my-crate"\n'
            'version = "0.1.0"\n'
            '\n'
            '[dependencies]\n'
            'serde = "1.0"\n'
            'tokio = { version = "1.30", features = ["rt"] }\n'
            'git-dep = { git = "https://example.com/x", rev = "abc123" }\n'
            'path-dep = { path = "../local" }\n'
        )
        (tmp_path / "Cargo.toml").write_text(
            cargo_toml, encoding="utf-8",
        )
        ctx = CargoContext.from_path(str(tmp_path / "Cargo.toml"))
        deps = {d.name: d for d in ctx.files[0].dependencies}
        assert deps["serde"].version == "1.0"
        assert deps["tokio"].version == "1.30"
        assert deps["git-dep"].is_git
        assert deps["git-dep"].git_rev == "abc123"
        assert not deps["git-dep"].git_mutable
        assert deps["path-dep"].is_path

    def test_workspace_root_skip(self, tmp_path):
        cargo_toml = (
            '[workspace]\n'
            'members = ["foo"]\n'
        )
        (tmp_path / "Cargo.toml").write_text(
            cargo_toml, encoding="utf-8",
        )
        ctx = CargoContext.from_path(str(tmp_path / "Cargo.toml"))
        assert ctx.files[0].is_workspace_root


# ── CARGO-001 ────────────────────────────────────────────────


class TestCargo001:
    def test_passes_on_exact_pin(self, tmp_path):
        cargo_toml = (
            '[package]\nname = "x"\nversion = "0.1.0"\n'
            '[dependencies]\nserde = "=1.0.190"\n'
        )
        findings = _scan(tmp_path, cargo_toml, has_lock=True)
        assert findings["CARGO-001"].passed

    def test_fires_on_caret_equivalent(self, tmp_path):
        cargo_toml = (
            '[package]\nname = "x"\nversion = "0.1.0"\n'
            '[dependencies]\nserde = "1.0"\n'
        )
        findings = _scan(tmp_path, cargo_toml, has_lock=True)
        assert not findings["CARGO-001"].passed

    def test_fires_on_explicit_caret(self, tmp_path):
        cargo_toml = (
            '[package]\nname = "x"\nversion = "0.1.0"\n'
            '[dependencies]\ntokio = "^1.30"\n'
        )
        findings = _scan(tmp_path, cargo_toml, has_lock=True)
        assert not findings["CARGO-001"].passed


# ── CARGO-002 ────────────────────────────────────────────────


class TestCargo002:
    def test_passes_when_git_dep_has_rev(self, tmp_path):
        cargo_toml = (
            '[package]\nname = "x"\nversion = "0.1.0"\n'
            '[dependencies]\n'
            'utility = { git = "https://example.com/u", rev = "abc" }\n'
        )
        findings = _scan(tmp_path, cargo_toml, has_lock=True)
        assert findings["CARGO-002"].passed

    def test_fires_on_tag_pin(self, tmp_path):
        cargo_toml = (
            '[package]\nname = "x"\nversion = "0.1.0"\n'
            '[dependencies]\n'
            'utility = { git = "https://example.com/u", tag = "v1" }\n'
        )
        findings = _scan(tmp_path, cargo_toml, has_lock=True)
        assert not findings["CARGO-002"].passed

    def test_fires_on_unspecified_git_ref(self, tmp_path):
        cargo_toml = (
            '[package]\nname = "x"\nversion = "0.1.0"\n'
            '[dependencies]\n'
            'utility = { git = "https://example.com/u" }\n'
        )
        findings = _scan(tmp_path, cargo_toml, has_lock=True)
        assert not findings["CARGO-002"].passed


# ── CARGO-003 ────────────────────────────────────────────────


class TestCargo003:
    def test_fires_when_no_lockfile(self, tmp_path):
        cargo_toml = (
            '[package]\nname = "x"\nversion = "0.1.0"\n'
            '[dependencies]\nserde = "=1.0.190"\n'
        )
        findings = _scan(tmp_path, cargo_toml, has_lock=False)
        assert not findings["CARGO-003"].passed

    def test_passes_when_lockfile_present(self, tmp_path):
        cargo_toml = (
            '[package]\nname = "x"\nversion = "0.1.0"\n'
            '[dependencies]\nserde = "=1.0.190"\n'
        )
        findings = _scan(tmp_path, cargo_toml, has_lock=True)
        assert findings["CARGO-003"].passed

    def test_passes_when_no_deps(self, tmp_path):
        cargo_toml = '[package]\nname = "x"\nversion = "0.1.0"\n'
        findings = _scan(tmp_path, cargo_toml, has_lock=False)
        assert findings["CARGO-003"].passed

    def test_passes_when_workspace_root(self, tmp_path):
        cargo_toml = '[workspace]\nmembers = ["foo"]\n'
        findings = _scan(tmp_path, cargo_toml, has_lock=False)
        assert findings["CARGO-003"].passed


# ── CARGO-004 ────────────────────────────────────────────────


class TestCargo004:
    def test_fires_on_path_dep_in_package_manifest(self, tmp_path):
        cargo_toml = (
            '[package]\nname = "x"\nversion = "0.1.0"\n'
            '[dependencies]\nlocal = { path = "../local" }\n'
        )
        findings = _scan(tmp_path, cargo_toml, has_lock=True)
        assert not findings["CARGO-004"].passed

    def test_workspace_root_exempt(self, tmp_path):
        cargo_toml = (
            '[workspace]\n'
            '[workspace.dependencies]\n'
            'shared = { path = "shared" }\n'
        )
        findings = _scan(tmp_path, cargo_toml, has_lock=True)
        assert findings["CARGO-004"].passed


# ── CARGO-005 ────────────────────────────────────────────────


class TestCargo005:
    def test_passes_on_default_registry(self, tmp_path):
        cargo_toml = (
            '[package]\nname = "x"\nversion = "0.1.0"\n'
            '[dependencies]\nserde = "=1.0.0"\n'
        )
        findings = _scan(tmp_path, cargo_toml, has_lock=True)
        assert findings["CARGO-005"].passed

    def test_fires_on_alternate_registry(self, tmp_path):
        cargo_toml = (
            '[package]\nname = "x"\nversion = "0.1.0"\n'
            '[dependencies]\n'
            'internal = { version = "=1.0.0", registry = "corp" }\n'
        )
        findings = _scan(tmp_path, cargo_toml, has_lock=True)
        assert not findings["CARGO-005"].passed


# ── CARGO-006 ────────────────────────────────────────────────


class TestCargo006:
    def test_passes_with_no_match(self, tmp_path):
        cargo_toml = (
            '[package]\nname = "x"\nversion = "0.1.0"\n'
            '[dependencies]\nserde = "=1.0.190"\n'
        )
        findings = _scan(tmp_path, cargo_toml, has_lock=True)
        assert findings["CARGO-006"].passed

    def test_fires_on_compromised_entry(self, tmp_path):
        from pipeline_check.core.checks.cargo._compromised_crates import (
            COMPROMISED,
        )
        seed = COMPROMISED[0]
        cargo_toml = (
            '[package]\nname = "x"\nversion = "0.1.0"\n'
            f'[dependencies]\n{seed.crate} = "={seed.malicious_versions[0]}"\n'
        )
        findings = _scan(tmp_path, cargo_toml, has_lock=True)
        assert not findings["CARGO-006"].passed


# ── End-to-end provider routing ──────────────────────────────


def test_provider_in_registry():
    from pipeline_check.core.providers import available
    assert "cargo" in available()


def test_provider_raises_without_path():
    from pipeline_check.core.providers import get
    prov = get("cargo")
    with pytest.raises(ValueError, match="cargo-path"):
        prov.build_context()
