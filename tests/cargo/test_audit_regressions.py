"""Regression tests from the 2026-07 rule audit (Cargo LOW findings)."""
from __future__ import annotations

import pathlib

from pipeline_check.core.checks.cargo.base import CargoContext
from pipeline_check.core.checks.cargo.pipelines import CargoChecks


def _scan(
    tmp_path: pathlib.Path,
    manifest: str,
    *,
    build_rs: str | None = None,
    lockfile: str | None = "# auto\n",
):
    (tmp_path / "Cargo.toml").write_text(manifest, encoding="utf-8")
    if build_rs is not None:
        (tmp_path / "build.rs").write_text(build_rs, encoding="utf-8")
    if lockfile is not None:
        (tmp_path / "Cargo.lock").write_text(lockfile, encoding="utf-8")
    ctx = CargoContext.from_path(str(tmp_path / "Cargo.toml"))
    return {f.check_id: f for f in CargoChecks(ctx).run()}


class TestAudit202607LowCargoC1:
    def test_cargo005_registry_index_url_is_alternate_registry(self, tmp_path):
        # ``registry-index`` points a dep at an arbitrary index URL,
        # bypassing crates.io like a named alternate registry.
        manifest = (
            '[package]\nname = "x"\nversion = "0.1.0"\n'
            '[dependencies]\n'
            'foo = { version = "1.0", '
            'registry-index = "https://alt.example/index" }\n'
        )
        findings = _scan(tmp_path, manifest)
        assert findings["CARGO-005"].passed is False
        assert "alt.example" in findings["CARGO-005"].description

    def test_cargo005_default_registry_still_passes(self, tmp_path):
        manifest = (
            '[package]\nname = "x"\nversion = "0.1.0"\n'
            '[dependencies]\nserde = "1"\n'
        )
        findings = _scan(tmp_path, manifest)
        assert findings["CARGO-005"].passed is True

    def test_cargo011_idiom_after_url_literal_is_seen(self, tmp_path):
        # The ``//`` inside a URL string literal must not eat the rest of
        # the line and hide the following network-egress idiom.
        manifest = '[package]\nname = "x"\nversion = "0.1.0"\n'
        build_rs = (
            'fn main() {\n'
            '    let u = "http://x.test";\n'
            '    let _r = reqwest::blocking::get(u);\n'
            '}\n'
        )
        findings = _scan(tmp_path, manifest, build_rs=build_rs)
        assert findings["CARGO-011"].passed is False
        assert "network egress" in findings["CARGO-011"].description

    def test_cargo011_comment_only_mention_still_passes(self, tmp_path):
        # A genuine comment mention must still be ignored.
        manifest = '[package]\nname = "x"\nversion = "0.1.0"\n'
        build_rs = (
            'fn main() {\n'
            '    // reqwest::blocking::get is intentionally not used here\n'
            '    println!("hello");\n'
            '}\n'
        )
        findings = _scan(tmp_path, manifest, build_rs=build_rs)
        assert findings["CARGO-011"].passed is True
