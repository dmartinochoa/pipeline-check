"""JSON schema contract tests — verify report_json output always matches the schema."""

import json
from pathlib import Path

import jsonschema
import pytest

from pipeline_check.core.checks.base import Finding, Severity
from pipeline_check.core.reporter import report_json
from pipeline_check.core.scorer import score

_SCHEMA = json.loads((Path(__file__).parent / "report_schema.json").read_text())


def _finding(check_id="CB-001", passed=True, severity=Severity.HIGH):
    return Finding(
        check_id=check_id,
        title="Test finding",
        severity=severity,
        resource="test-resource",
        description="Test description.",
        recommendation="Test recommendation.",
        owasp_cicd="CICD-SEC-1: Test",
        passed=passed,
    )


def _report(findings):
    return json.loads(report_json(findings, score(findings)))


class TestSchemaCompliance:
    def test_passing_scan(self):
        jsonschema.validate(_report([_finding(passed=True)]), _SCHEMA)

    def test_failing_scan(self):
        jsonschema.validate(_report([_finding(passed=False)]), _SCHEMA)

    def test_empty_findings(self):
        jsonschema.validate(_report([]), _SCHEMA)

    def test_all_severities_represented(self):
        findings = [
            _finding(check_id=f"CB-00{i+1}", severity=sev)
            for i, sev in enumerate(Severity)
        ]
        jsonschema.validate(_report(findings), _SCHEMA)

    def test_grade_d_report(self):
        findings = [
            _finding(passed=False, severity=Severity.CRITICAL)
            for _ in range(10)
        ]
        report = _report(findings)
        assert report["score"]["grade"] == "D"
        jsonschema.validate(report, _SCHEMA)

    def test_score_within_bounds(self):
        for passed in (True, False):
            report = _report([_finding(passed=passed, severity=Severity.CRITICAL)])
            assert 0 <= report["score"]["score"] <= 100


class TestSchemaEnforcement:
    def test_invalid_grade_rejected(self):
        bad = {"score": {"score": 50, "grade": "F", "summary": {}}, "findings": []}
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(bad, _SCHEMA)

    def test_score_out_of_range_rejected(self):
        bad = {"score": {"score": 150, "grade": "A", "summary": {}}, "findings": []}
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(bad, _SCHEMA)

    def test_missing_passed_field_rejected(self):
        report = _report([_finding()])
        del report["findings"][0]["passed"]
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(report, _SCHEMA)

    def test_invalid_severity_rejected(self):
        report = _report([_finding()])
        report["findings"][0]["severity"] = "EXTREME"
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(report, _SCHEMA)

    def test_invalid_check_id_format_rejected(self):
        report = _report([_finding()])
        report["findings"][0]["check_id"] = "bad-id"
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(report, _SCHEMA)

    def test_extra_fields_rejected(self):
        report = _report([_finding()])
        report["unexpected_field"] = "value"
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(report, _SCHEMA)
