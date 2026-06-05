"""SARIF 2.1.0 schema-compliance tests.

Validates the reporter's output against the official SARIF 2.1.0 JSON
schema (vendored under ``tests/schemas/``). SARIF feeds GitHub code
scanning and other external tools, so a field that looks valid but
violates the spec breaks ingestion downstream while every internal
assertion still passes. These tests catch that class of regression.
"""
from __future__ import annotations

import json

import pytest

from pipeline_check.core.checks.base import (
    Confidence,
    Finding,
    Location,
    Severity,
)
from pipeline_check.core.sarif_reporter import report_sarif
from pipeline_check.core.standards.base import ControlRef

from .schema_validators import assert_valid, sarif_validator

_CTRL = ControlRef(
    standard="owasp_cicd_top_10",
    standard_title="OWASP Top 10 CI/CD Security Risks",
    control_id="CICD-SEC-1",
    control_title="Insufficient Flow Control Mechanisms",
)


def _f(check_id="CB-001", passed=False, severity=Severity.HIGH, **kw):
    return Finding(
        check_id=check_id,
        title=kw.get("title", "Plaintext secret in CodeBuild env"),
        severity=severity,
        resource=kw.get("resource", "my-project"),
        description=kw.get("description", "A secret was found."),
        recommendation=kw.get("recommendation", "Use Secrets Manager."),
        passed=passed,
        controls=kw.get("controls", [_CTRL]),
        cwe=kw.get("cwe", ["CWE-798"]),
        locations=kw.get("locations", []),
    )


def _score(grade="C", score=70):
    return {"grade": grade, "score": score, "total": 10, "failed": 3, "passed": 7}


def _validate(*args, **kwargs):
    assert_valid(json.loads(report_sarif(*args, **kwargs)), sarif_validator())


class TestSarifSchemaCompliance:
    def test_empty_findings(self):
        _validate([], _score())

    def test_single_failure(self):
        _validate([_f(passed=False)], _score(), tool_version="1.9.0")

    def test_passing_only_populates_catalog_without_results(self):
        # Passed findings complete the rule catalog but emit no results.
        _validate([_f(passed=True)], _score("A", 100))

    def test_mixed_pass_and_fail(self):
        _validate(
            [_f("CB-001", passed=False), _f("CB-002", passed=True)], _score()
        )

    def test_all_severities(self):
        findings = [
            _f(check_id=f"CB-00{i + 1}", passed=False, severity=sev)
            for i, sev in enumerate(Severity)
        ]
        _validate(findings, _score())

    def test_finding_with_locations(self):
        f = _f(
            passed=False,
            locations=[
                Location(path=".github/workflows/ci.yml", start_line=12),
                Location(
                    path=".github/workflows/ci.yml",
                    start_line=20,
                    end_line=24,
                    start_column=3,
                ),
            ],
        )
        _validate([f], _score())

    def test_finding_without_controls_or_cwe(self):
        _validate([_f(passed=False, controls=[], cwe=[])], _score())

    def test_inline_explain(self):
        _validate([_f(passed=False)], _score(), inline_explain=True)

    def test_with_attack_chain(self):
        from pipeline_check.core.chains import Chain

        chain = Chain(
            chain_id="AC-001",
            title="Fork PR reaches privileged context",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            summary="s",
            narrative="n",
            mitre_attack=["T1078"],
            kill_chain_phase="initial-access",
            triggering_check_ids=["GHA-002", "GHA-005"],
            triggering_findings=[],
            resources=["wf.yml"],
            references=[],
            recommendation="r",
        )
        _validate([_f(passed=False)], _score(), chains=[chain])


class TestSarifSchemaEnforcement:
    """Confirm the validator actually rejects malformed SARIF, so a green
    run above means the schema is doing work, not rubber-stamping."""

    def _report(self):
        return json.loads(report_sarif([_f(passed=False)], _score()))

    def test_missing_version_rejected(self):
        report = self._report()
        del report["version"]
        with pytest.raises(AssertionError):
            assert_valid(report, sarif_validator())

    def test_runs_wrong_type_rejected(self):
        report = self._report()
        report["runs"] = "not-an-array"
        with pytest.raises(AssertionError):
            assert_valid(report, sarif_validator())

    def test_invalid_result_level_rejected(self):
        report = self._report()
        report["runs"][0]["results"][0]["level"] = "catastrophic"
        with pytest.raises(AssertionError):
            assert_valid(report, sarif_validator())
