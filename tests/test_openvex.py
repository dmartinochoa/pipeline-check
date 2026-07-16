"""OpenVEX ingest (``--vex``) and emit (``--output openvex``)."""
from __future__ import annotations

import json

import pytest

from pipeline_check.core.checks.base import Finding, Severity, VulnRef
from pipeline_check.core.gate import GateConfig, evaluate_gate
from pipeline_check.core.openvex import VexError, load_vex
from pipeline_check.core.openvex_reporter import report_openvex


def _advisory(
    check_id: str = "NPM-010",
    resource: str = "package.json",
    vulns: tuple[VulnRef, ...] = (),
    passed: bool = False,
) -> Finding:
    return Finding(
        check_id=check_id,
        title="known OSV advisory",
        severity=Severity.CRITICAL,
        resource=resource,
        description="d",
        recommendation="r",
        passed=passed,
        vulnerabilities=vulns,
    )


def _misconfig() -> Finding:
    return Finding(
        check_id="GHA-002",
        title="misconfig",
        severity=Severity.HIGH,
        resource="ci.yml",
        description="d",
        recommendation="r",
        passed=False,
    )


_JSON5 = VulnRef("GHSA-jjjj", "pkg:npm/json5@2.2.1", ("CVE-2022-46175",))
_URLLIB3 = VulnRef("CVE-2023-1", "pkg:pypi/urllib3@2.0.4")


def _vex_doc(tmp_path, statements: list[dict]) -> str:
    doc = {"@context": "https://openvex.dev/ns/v0.2.0", "statements": statements}
    p = tmp_path / "vex.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    return str(p)


# ── Emit ────────────────────────────────────────────────────────────────


class TestEmit:
    def test_shape_and_status(self):
        doc = json.loads(report_openvex([_advisory(vulns=(_JSON5,))]))
        assert doc["@context"].endswith("v0.2.0")
        assert doc["author"] == "pipeline-check"
        assert len(doc["statements"]) == 1
        stmt = doc["statements"][0]
        assert stmt["status"] == "affected"
        assert stmt["vulnerability"]["name"] == "GHSA-jjjj"
        assert stmt["vulnerability"]["aliases"] == ["CVE-2022-46175"]
        assert stmt["products"] == [{"@id": "pkg:npm/json5@2.2.1"}]

    def test_only_advisory_findings_contribute(self):
        doc = json.loads(report_openvex(
            [_advisory(vulns=(_JSON5,)), _misconfig()],
        ))
        assert len(doc["statements"]) == 1

    def test_passed_findings_excluded(self):
        doc = json.loads(report_openvex(
            [_advisory(vulns=(_JSON5,), passed=True)],
        ))
        assert doc["statements"] == []

    def test_deterministic_id_independent_of_timestamp(self):
        import datetime as dt
        a = json.loads(report_openvex(
            [_advisory(vulns=(_JSON5,))],
            now=dt.datetime(2020, 1, 1, tzinfo=dt.UTC),
        ))
        b = json.loads(report_openvex(
            [_advisory(vulns=(_JSON5,))],
            now=dt.datetime(2026, 7, 16, tzinfo=dt.UTC),
        ))
        assert a["@id"] == b["@id"]
        assert a["timestamp"] != b["timestamp"]

    def test_products_merged_and_sorted_per_vuln(self):
        v_a = VulnRef("CVE-9", "pkg:npm/b@2.0")
        v_b = VulnRef("CVE-9", "pkg:npm/a@1.0")
        doc = json.loads(report_openvex(
            [_advisory(vulns=(v_a,)), _advisory(vulns=(v_b,))],
        ))
        assert len(doc["statements"]) == 1
        assert doc["statements"][0]["products"] == [
            {"@id": "pkg:npm/a@1.0"}, {"@id": "pkg:npm/b@2.0"},
        ]

    def test_empty_scan(self):
        doc = json.loads(report_openvex([]))
        assert doc["statements"] == []


# ── Ingest / match ──────────────────────────────────────────────────────


class TestIngest:
    def test_match_by_primary_id(self, tmp_path):
        path = _vex_doc(tmp_path, [{
            "vulnerability": {"name": "GHSA-jjjj"},
            "products": [{"@id": "pkg:npm/json5@2.2.1"}],
            "status": "not_affected",
        }])
        idx = load_vex([path])
        assert idx.match(_advisory(vulns=(_JSON5,))) is not None

    def test_match_by_alias_either_direction(self, tmp_path):
        # Document keys on the CVE; finding's primary id is the GHSA.
        path = _vex_doc(tmp_path, [{
            "vulnerability": {"name": "CVE-2022-46175"},
            "products": [{"@id": "pkg:npm/json5@2.2.1"}],
            "status": "fixed",
        }])
        idx = load_vex([path])
        m = idx.match(_advisory(vulns=(_JSON5,)))
        assert m is not None and m.status == "fixed"

    def test_affected_status_does_not_suppress(self, tmp_path):
        for status in ("affected", "under_investigation"):
            path = _vex_doc(tmp_path, [{
                "vulnerability": {"name": "GHSA-jjjj"},
                "products": [{"@id": "pkg:npm/json5@2.2.1"}],
                "status": status,
            }])
            assert load_vex([path]).match(_advisory(vulns=(_JSON5,))) is None

    def test_product_must_match(self, tmp_path):
        path = _vex_doc(tmp_path, [{
            "vulnerability": {"name": "GHSA-jjjj"},
            "products": [{"@id": "pkg:npm/other@1.0.0"}],
            "status": "fixed",
        }])
        assert load_vex([path]).match(_advisory(vulns=(_JSON5,))) is None

    def test_versionless_product_covers_all_versions(self, tmp_path):
        path = _vex_doc(tmp_path, [{
            "vulnerability": {"name": "GHSA-jjjj"},
            "products": [{"@id": "pkg:npm/json5"}],
            "status": "not_affected",
        }])
        assert load_vex([path]).match(_advisory(vulns=(_JSON5,))) is not None

    def test_bare_string_vulnerability_and_product(self, tmp_path):
        # OpenVEX 0.0.1 shape: string vuln, string product.
        path = _vex_doc(tmp_path, [{
            "vulnerability": "GHSA-jjjj",
            "products": ["pkg:npm/json5@2.2.1"],
            "status": "fixed",
        }])
        assert load_vex([path]).match(_advisory(vulns=(_JSON5,))) is not None

    def test_subcomponent_purl_identifier(self, tmp_path):
        path = _vex_doc(tmp_path, [{
            "vulnerability": {"name": "GHSA-jjjj"},
            "products": [{
                "@id": "SPDXRef-x",
                "identifiers": {"purl": "pkg:npm/json5@2.2.1"},
            }],
            "status": "fixed",
        }])
        assert load_vex([path]).match(_advisory(vulns=(_JSON5,))) is not None

    def test_misconfig_finding_never_matches(self, tmp_path):
        path = _vex_doc(tmp_path, [{
            "vulnerability": {"name": "GHSA-jjjj"},
            "products": [{"@id": "pkg:npm/json5@2.2.1"}],
            "status": "fixed",
        }])
        assert load_vex([path]).match(_misconfig()) is None

    def test_justification_carried(self, tmp_path):
        path = _vex_doc(tmp_path, [{
            "vulnerability": {"name": "GHSA-jjjj"},
            "products": [{"@id": "pkg:npm/json5@2.2.1"}],
            "status": "not_affected",
            "justification": "vulnerable_code_not_in_execute_path",
        }])
        m = load_vex([path]).match(_advisory(vulns=(_JSON5,)))
        assert m is not None
        assert "vulnerable_code_not_in_execute_path" in m.summary()


# ── Loader errors ───────────────────────────────────────────────────────


class TestLoaderErrors:
    def test_missing_file(self, tmp_path):
        with pytest.raises(VexError, match="could not read"):
            load_vex([str(tmp_path / "nope.json")])

    def test_invalid_json(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("{ not json", encoding="utf-8")
        with pytest.raises(VexError, match="invalid JSON"):
            load_vex([str(p)])

    def test_missing_statements_array(self, tmp_path):
        p = tmp_path / "x.json"
        p.write_text('{"@context": "x"}', encoding="utf-8")
        with pytest.raises(VexError, match="statements"):
            load_vex([str(p)])

    def test_empty_document_is_falsy(self, tmp_path):
        path = _vex_doc(tmp_path, [])
        assert not load_vex([path])

    def test_multiple_documents_merge(self, tmp_path):
        d1 = tmp_path / "a.json"
        d1.write_text(json.dumps({"statements": [{
            "vulnerability": {"name": "GHSA-jjjj"},
            "products": [{"@id": "pkg:npm/json5@2.2.1"}],
            "status": "fixed",
        }]}), encoding="utf-8")
        d2 = tmp_path / "b.json"
        d2.write_text(json.dumps({"statements": [{
            "vulnerability": {"name": "CVE-2023-1"},
            "products": [{"@id": "pkg:pypi/urllib3@2.0.4"}],
            "status": "not_affected",
        }]}), encoding="utf-8")
        idx = load_vex([str(d1), str(d2)])
        assert idx.match(_advisory(vulns=(_JSON5,))) is not None
        assert idx.match(_advisory(vulns=(_URLLIB3,))) is not None


# ── Gate integration ────────────────────────────────────────────────────


class TestGateIntegration:
    def test_vex_partitions_out_of_effective(self, tmp_path):
        path = _vex_doc(tmp_path, [{
            "vulnerability": {"name": "CVE-2022-46175"},
            "products": [{"@id": "pkg:npm/json5@2.2.1"}],
            "status": "fixed",
        }])
        idx = load_vex([path])
        findings = [
            _advisory(vulns=(_JSON5,)),
            _advisory(check_id="PYPI-009", resource="requirements.txt",
                      vulns=(_URLLIB3,)),
            _misconfig(),
        ]
        gr = evaluate_gate(
            findings, {"grade": "F", "score": 0}, GateConfig(vex_index=idx),
        )
        assert [f.check_id for f in gr.vex_suppressed] == ["NPM-010"]
        assert "NPM-010" not in {f.check_id for f in gr.effective}
        assert "PYPI-009" in {f.check_id for f in gr.effective}

    def test_no_vex_no_suppression(self):
        gr = evaluate_gate(
            [_advisory(vulns=(_JSON5,))], {"grade": "F", "score": 0},
            GateConfig(),
        )
        assert gr.vex_suppressed == []


# ── Round-trip ──────────────────────────────────────────────────────────


def test_emit_then_ingest_round_trip(tmp_path):
    """Emit the scan's advisory findings, flip a status to fixed, and
    confirm the same finding is then VEX-suppressed on ingest."""
    finding = _advisory(vulns=(_JSON5,))
    emitted = json.loads(report_openvex([finding]))
    # Operator triages: mark the emitted statement fixed and feed it back.
    for stmt in emitted["statements"]:
        stmt["status"] = "fixed"
    p = tmp_path / "triaged.vex.json"
    p.write_text(json.dumps(emitted), encoding="utf-8")
    idx = load_vex([str(p)])
    assert idx.match(finding) is not None
