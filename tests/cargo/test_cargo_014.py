"""Per-rule unit tests for CARGO-014 (missing supply-chain audit gate)."""
from __future__ import annotations

import pathlib

from pipeline_check.core.checks.cargo.base import CargoContext
from pipeline_check.core.checks.cargo.pipelines import CargoChecks

_MANIFEST = '[package]\nname = "x"\nversion = "0.1.0"\n[dependencies]\nserde = "1"\n'
_NO_DEPS = '[package]\nname = "x"\nversion = "0.1.0"\n'


def _scan(tmp_path: pathlib.Path, *, manifest: str = _MANIFEST, gate: str | None = None):
    (tmp_path / "Cargo.toml").write_text(manifest, encoding="utf-8")
    if gate is not None:
        path = tmp_path / gate
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# gate\n", encoding="utf-8")
    ctx = CargoContext.from_path(str(tmp_path / "Cargo.toml"))
    return {f.check_id: f for f in CargoChecks(ctx).run()}


class TestCargo014MissingAuditGate:
    def test_fires_when_no_gate(self, tmp_path):
        findings = _scan(tmp_path)
        assert not findings["CARGO-014"].passed

    def test_passes_with_deny_toml(self, tmp_path):
        findings = _scan(tmp_path, gate="deny.toml")
        assert findings["CARGO-014"].passed

    def test_passes_with_cargo_vet(self, tmp_path):
        findings = _scan(tmp_path, gate="supply-chain/config.toml")
        assert findings["CARGO-014"].passed

    def test_passes_with_audit_toml(self, tmp_path):
        findings = _scan(tmp_path, gate="audit.toml")
        assert findings["CARGO-014"].passed

    def test_passes_when_no_dependencies(self, tmp_path):
        findings = _scan(tmp_path, manifest=_NO_DEPS)
        assert findings["CARGO-014"].passed
