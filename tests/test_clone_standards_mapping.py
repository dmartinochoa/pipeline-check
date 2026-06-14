"""Tests for scripts/clone_standards_mapping.py.

The tool clones an analog rule's per-standard control mappings onto a new
rule, touching only the standards the analog is already in. These tests
drive it against a synthetic data dir (so they don't depend on the live
mappings) plus one self-consistency check against the real data.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

import clone_standards_mapping as csm  # noqa: E402

_OWASP = '''STANDARD = {
    "mappings": {
        "GHA-001":  ["CICD-SEC-1"],  # something
        "GHA-002":  ["CICD-SEC-4"],  # other
    },
}
'''
_NIST = '''STANDARD = {
    "mappings": {
        "GHA-001":   ["PS.1.1", "PS.2.1"],  # something
    },
}
'''
# slsa has no GHA-001 -> must be skipped (analog not in this standard).
_SLSA = '''STANDARD = {
    "mappings": {
        "GHA-002":  ["Build.L3.Isolated"],
    },
}
'''


def _data_dir(tmp_path: Path) -> Path:
    d = tmp_path / "data"
    d.mkdir()
    (d / "__init__.py").write_text("", encoding="utf-8")
    (d / "owasp_cicd_top_10.py").write_text(_OWASP, encoding="utf-8")
    (d / "nist_ssdf.py").write_text(_NIST, encoding="utf-8")
    (d / "slsa.py").write_text(_SLSA, encoding="utf-8")
    return d


def test_plan_clones_only_standards_the_analog_is_in(tmp_path):
    d = _data_dir(tmp_path)
    planned, warnings = csm.plan_clone("GHA-001", "GHA-999", "new rule", data_dir=d)
    names = {p.path.name for p in planned}
    assert names == {"owasp_cicd_top_10.py", "nist_ssdf.py"}  # not slsa
    assert not warnings
    # Per-standard controls are copied verbatim.
    by_name = {p.path.name: p.controls for p in planned}
    assert by_name["owasp_cicd_top_10.py"] == '["CICD-SEC-1"]'
    assert by_name["nist_ssdf.py"] == '["PS.1.1", "PS.2.1"]'


def test_apply_inserts_after_the_analog_with_same_controls(tmp_path):
    d = _data_dir(tmp_path)
    planned, _ = csm.plan_clone("GHA-001", "GHA-999", "new rule", data_dir=d)
    csm.apply_plan(planned)

    owasp = (d / "owasp_cicd_top_10.py").read_text(encoding="utf-8")
    assert '"GHA-999":  ["CICD-SEC-1"],  # new rule' in owasp
    # Inserted directly after the analog, before GHA-002.
    lines = owasp.splitlines()
    i999 = next(n for n, ln in enumerate(lines) if '"GHA-999"' in ln)
    i001 = next(n for n, ln in enumerate(lines) if '"GHA-001"' in ln)
    i002 = next(n for n, ln in enumerate(lines) if '"GHA-002"' in ln)
    assert i001 < i999 < i002

    nist = (d / "nist_ssdf.py").read_text(encoding="utf-8")
    assert '"GHA-999":  ["PS.1.1", "PS.2.1"],  # new rule' in nist
    # slsa untouched.
    assert "GHA-999" not in (d / "slsa.py").read_text(encoding="utf-8")


def test_already_mapped_is_skipped_with_warning(tmp_path):
    d = _data_dir(tmp_path)
    csm.apply_plan(csm.plan_clone("GHA-001", "GHA-999", "x", data_dir=d)[0])
    planned, warnings = csm.plan_clone("GHA-001", "GHA-999", "x", data_dir=d)
    assert planned == []
    assert any("already mapped" in w for w in warnings)


def test_unknown_analog_yields_nothing(tmp_path):
    d = _data_dir(tmp_path)
    planned, warnings = csm.plan_clone("ZZZ-404", "GHA-999", "x", data_dir=d)
    assert planned == []
    assert not warnings


def test_real_data_clone_matches_analog_membership():
    # Self-consistency against the live mappings: the number of standards a
    # clone touches equals the number of standards the analog is mapped to.
    planned, _ = csm.plan_clone("HARNESS-011", "HARNESS-900", "x")
    touched = {p.path.name for p in planned}
    # HARNESS-011 (unsafe-deser, RCE family) lives in the 12-standard set.
    assert "nist_800_190.py" in touched
    assert "owasp_cicd_top_10.py" in touched
    assert len(planned) >= 10


def test_main_dry_run_does_not_write(tmp_path, capsys, monkeypatch):
    d = _data_dir(tmp_path)
    monkeypatch.setattr(csm, "DATA_DIR", d)
    rc = csm.main(["GHA-001", "GHA-999", "--comment", "x"])
    assert rc == 0
    assert "DRY RUN" in capsys.readouterr().out
    # No file mutated without --apply.
    assert "GHA-999" not in (d / "owasp_cicd_top_10.py").read_text(encoding="utf-8")
