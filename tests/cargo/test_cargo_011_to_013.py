"""Per-rule unit tests for CARGO-011..013 (Cargo build-exec / source pack)."""
from __future__ import annotations

import pathlib

from pipeline_check.core.checks.cargo.base import CargoContext
from pipeline_check.core.checks.cargo.pipelines import CargoChecks

_MANIFEST = '[package]\nname = "x"\nversion = "0.1.0"\n[dependencies]\nserde = "1"\n'


def _scan(
    tmp_path: pathlib.Path,
    *,
    build_rs: str | None = None,
    cargo_config: str | None = None,
    lockfile: str | None = "# auto\n",
):
    (tmp_path / "Cargo.toml").write_text(_MANIFEST, encoding="utf-8")
    if build_rs is not None:
        (tmp_path / "build.rs").write_text(build_rs, encoding="utf-8")
    if cargo_config is not None:
        (tmp_path / ".cargo").mkdir(exist_ok=True)
        (tmp_path / ".cargo" / "config.toml").write_text(
            cargo_config, encoding="utf-8",
        )
    if lockfile is not None:
        (tmp_path / "Cargo.lock").write_text(lockfile, encoding="utf-8")
    ctx = CargoContext.from_path(str(tmp_path / "Cargo.toml"))
    return {f.check_id: f for f in CargoChecks(ctx).run()}


# ── CARGO-011 (build.rs egress / exec) ──────────────────────────


class TestCargo011BuildRs:
    def test_passes_with_no_build_rs(self, tmp_path):
        findings = _scan(tmp_path)
        assert findings["CARGO-011"].passed

    def test_passes_on_benign_build_rs(self, tmp_path):
        findings = _scan(tmp_path, build_rs="fn main() {}\n")
        assert findings["CARGO-011"].passed

    def test_fires_on_network_idiom(self, tmp_path):
        bs = 'fn main(){ let _=ureq::get("https://x.test").call(); }\n'
        findings = _scan(tmp_path, build_rs=bs)
        assert not findings["CARGO-011"].passed
        assert "network" in findings["CARGO-011"].description

    def test_fires_on_process_command(self, tmp_path):
        bs = (
            "use std::process::Command;\n"
            'fn main(){ Command::new("sh"); }\n'
        )
        findings = _scan(tmp_path, build_rs=bs)
        assert not findings["CARGO-011"].passed

    def test_fires_on_include(self, tmp_path):
        bs = 'fn main(){ include!("/tmp/generated.rs"); }\n'
        findings = _scan(tmp_path, build_rs=bs)
        assert not findings["CARGO-011"].passed

    def test_skips_idiom_in_comment(self, tmp_path):
        bs = "fn main(){ /* ureq::get */ }\n// std::net here\n"
        findings = _scan(tmp_path, build_rs=bs)
        assert findings["CARGO-011"].passed


# ── CARGO-012 (.cargo/config.toml override) ─────────────────────


class TestCargo012CargoConfig:
    def test_passes_with_no_config(self, tmp_path):
        findings = _scan(tmp_path)
        assert findings["CARGO-012"].passed

    def test_fires_on_source_replace_with(self, tmp_path):
        cfg = (
            "[source.crates-io]\n"
            'replace-with = "mirror"\n'
            "[source.mirror]\n"
            'registry = "https://crates.internal/index"\n'
        )
        findings = _scan(tmp_path, cargo_config=cfg)
        assert not findings["CARGO-012"].passed
        assert "replace-with" in findings["CARGO-012"].description

    def test_fires_on_linker_rustflags(self, tmp_path):
        cfg = "[build]\nrustflags = [\"-Clinker=/tmp/pwn\"]\n"
        findings = _scan(tmp_path, cargo_config=cfg)
        assert not findings["CARGO-012"].passed

    def test_passes_on_benign_rustflags(self, tmp_path):
        cfg = '[build]\nrustflags = ["-Copt-level=3"]\n'
        findings = _scan(tmp_path, cargo_config=cfg)
        assert findings["CARGO-012"].passed


# ── CARGO-013 (Cargo.lock off-crates.io source) ─────────────────


class TestCargo013LockfileSource:
    def test_passes_on_crates_io_sources(self, tmp_path):
        lock = (
            "[[package]]\n"
            'name = "serde"\n'
            'version = "1.0.0"\n'
            'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
        )
        findings = _scan(tmp_path, lockfile=lock)
        assert findings["CARGO-013"].passed

    def test_fires_on_git_source(self, tmp_path):
        lock = (
            "[[package]]\n"
            'name = "useful-helper"\n'
            'version = "1.2.3"\n'
            'source = "git+https://github.com/attacker/useful-helper"\n'
        )
        findings = _scan(tmp_path, lockfile=lock)
        assert not findings["CARGO-013"].passed
        assert "useful-helper" in findings["CARGO-013"].description

    def test_fires_on_alternate_registry(self, tmp_path):
        lock = (
            "[[package]]\n"
            'name = "internal"\n'
            'version = "0.1.0"\n'
            'source = "registry+https://crates.attacker.test/index"\n'
        )
        findings = _scan(tmp_path, lockfile=lock)
        assert not findings["CARGO-013"].passed

    def test_skips_package_without_source(self, tmp_path):
        # A workspace member / path dep has no source line.
        lock = (
            "[[package]]\n"
            'name = "x"\n'
            'version = "0.1.0"\n'
        )
        findings = _scan(tmp_path, lockfile=lock)
        assert findings["CARGO-013"].passed
