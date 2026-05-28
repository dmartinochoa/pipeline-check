"""Per-rule unit tests for CARGO-007..010 (Cargo extended pack)."""
from __future__ import annotations

import pathlib

from pipeline_check.core.checks.cargo.base import CargoContext
from pipeline_check.core.checks.cargo.pipelines import CargoChecks


def _scan(tmp_path: pathlib.Path, cargo_toml: str, has_lock: bool = True):
    (tmp_path / "Cargo.toml").write_text(cargo_toml, encoding="utf-8")
    if has_lock:
        (tmp_path / "Cargo.lock").write_text("", encoding="utf-8")
    ctx = CargoContext.from_path(str(tmp_path / "Cargo.toml"))
    return {f.check_id: f for f in CargoChecks(ctx).run()}


# ── CARGO-007 ───────────────────────────────────────────────────


class TestCARGO007BuildDepsFloating:
    def test_fires_on_floating_build_dep(self, tmp_path):
        body = (
            '[package]\nname = "x"\nversion = "0.1.0"\n'
            'rust-version = "1.75"\n'
            '[build-dependencies]\n'
            'tonic-build = "0.12"\n'
        )
        findings = _scan(tmp_path, body)
        assert not findings["CARGO-007"].passed

    def test_passes_on_exact_pin(self, tmp_path):
        body = (
            '[package]\nname = "x"\nversion = "0.1.0"\n'
            'rust-version = "1.75"\n'
            '[build-dependencies]\n'
            'tonic-build = "=0.12.3"\n'
        )
        findings = _scan(tmp_path, body)
        assert findings["CARGO-007"].passed

    def test_passes_with_no_build_deps(self, tmp_path):
        body = (
            '[package]\nname = "x"\nversion = "0.1.0"\n'
            'rust-version = "1.75"\n'
        )
        findings = _scan(tmp_path, body)
        assert findings["CARGO-007"].passed


# ── CARGO-008 ───────────────────────────────────────────────────


class TestCARGO008PatchCratesIo:
    def test_passes_when_no_patch_table(self, tmp_path):
        body = (
            '[package]\nname = "x"\nversion = "0.1.0"\n'
            'rust-version = "1.75"\n'
        )
        findings = _scan(tmp_path, body)
        assert findings["CARGO-008"].passed

    def test_fires_on_git_patch(self, tmp_path):
        body = (
            '[package]\nname = "x"\nversion = "0.1.0"\n'
            'rust-version = "1.75"\n'
            '[patch.crates-io]\n'
            'upstream = { git = "https://github.com/attacker/fork" }\n'
        )
        findings = _scan(tmp_path, body)
        assert not findings["CARGO-008"].passed
        assert "upstream" in findings["CARGO-008"].description

    def test_fires_on_path_patch(self, tmp_path):
        body = (
            '[package]\nname = "x"\nversion = "0.1.0"\n'
            'rust-version = "1.75"\n'
            '[patch.crates-io]\n'
            'upstream = { path = "../local-fork" }\n'
        )
        findings = _scan(tmp_path, body)
        assert not findings["CARGO-008"].passed


# ── CARGO-009 ───────────────────────────────────────────────────


class TestCARGO009WorkspaceDepsFloating:
    def test_fires_on_floating_workspace_dep(self, tmp_path):
        body = (
            '[workspace]\nmembers = ["foo"]\n'
            '[workspace.dependencies]\n'
            'serde = "1.0"\n'
        )
        findings = _scan(tmp_path, body)
        assert not findings["CARGO-009"].passed

    def test_passes_on_exact_pin(self, tmp_path):
        body = (
            '[workspace]\nmembers = ["foo"]\n'
            '[workspace.dependencies]\n'
            'serde = "=1.0.190"\n'
        )
        findings = _scan(tmp_path, body)
        assert findings["CARGO-009"].passed

    def test_passes_with_no_workspace_deps(self, tmp_path):
        body = (
            '[package]\nname = "x"\nversion = "0.1.0"\n'
            'rust-version = "1.75"\n'
        )
        findings = _scan(tmp_path, body)
        assert findings["CARGO-009"].passed


# ── CARGO-010 ───────────────────────────────────────────────────


class TestCARGO010MissingRustVersion:
    def test_fires_when_field_absent(self, tmp_path):
        body = (
            '[package]\nname = "x"\nversion = "0.1.0"\n'
        )
        findings = _scan(tmp_path, body)
        assert not findings["CARGO-010"].passed

    def test_passes_with_explicit_rust_version(self, tmp_path):
        body = (
            '[package]\nname = "x"\nversion = "0.1.0"\n'
            'rust-version = "1.75"\n'
        )
        findings = _scan(tmp_path, body)
        assert findings["CARGO-010"].passed

    def test_passes_with_workspace_inheritance(self, tmp_path):
        body = (
            '[package]\nname = "x"\nversion = "0.1.0"\n'
            'rust-version = { workspace = true }\n'
        )
        findings = _scan(tmp_path, body)
        assert findings["CARGO-010"].passed

    def test_workspace_root_skipped(self, tmp_path):
        body = (
            '[workspace]\nmembers = ["x"]\n'
        )
        findings = _scan(tmp_path, body)
        assert findings["CARGO-010"].passed
