"""Tests for the CI-gate module.

Covers every gate condition in isolation, their interactions, and the
two subtractive filters (baseline + ignore file).
"""
from __future__ import annotations

import json

import pytest

from pipeline_check.core.checks.base import Finding, Severity
from pipeline_check.core.gate import (
    GateConfig,
    IgnoreRule,
    evaluate_gate,
    load_baseline,
    load_ignore_file,
)


def _f(check_id="CB-001", resource="proj-a", severity=Severity.HIGH, passed=False):
    return Finding(
        check_id=check_id,
        title="t",
        severity=severity,
        resource=resource,
        description="d",
        recommendation="r",
        passed=passed,
    )


def _score(grade="B"):
    return {"grade": grade, "total": 10, "failed": 2, "passed": 8}


# ────────────────────────────────────────────────────────────────────────────
# Default gate (--fail-on CRITICAL, implicit)
# ────────────────────────────────────────────────────────────────────────────


class TestDefaultGate:
    def test_critical_fails_by_default(self):
        r = evaluate_gate(
            [_f(severity=Severity.CRITICAL)], _score("A"), GateConfig(),
        )
        assert not r.passed
        assert r.exit_code == 1
        assert any("default gate" in x for x in r.reasons)

    def test_high_passes_by_default(self):
        """Only CRITICAL should trip the default gate — HIGH et al. don't."""
        r = evaluate_gate(
            [_f(severity=Severity.HIGH)], _score("D"), GateConfig(),
        )
        assert r.passed

    def test_grade_d_no_critical_still_passes(self):
        """Grade-D repos with no CRITICAL findings pass the default gate.
        This is a deliberate change from the prior grade-D fallback."""
        r = evaluate_gate(
            [_f(severity=Severity.HIGH) for _ in range(10)],
            _score("D"),
            GateConfig(),
        )
        assert r.passed

    def test_no_findings_passes(self):
        r = evaluate_gate([], _score("A"), GateConfig())
        assert r.passed

    def test_passed_critical_does_not_trip_default(self):
        r = evaluate_gate(
            [_f(severity=Severity.CRITICAL, passed=True)], _score("A"),
            GateConfig(),
        )
        assert r.passed


# ────────────────────────────────────────────────────────────────────────────
# --fail-on SEVERITY
# ────────────────────────────────────────────────────────────────────────────


class TestFailOnSeverity:
    def test_fail_on_high_trips_on_high(self):
        r = evaluate_gate([_f(severity=Severity.HIGH)], _score("B"),
                          GateConfig(fail_on=Severity.HIGH))
        assert not r.passed

    def test_fail_on_high_trips_on_critical(self):
        r = evaluate_gate([_f(severity=Severity.CRITICAL)], _score("B"),
                          GateConfig(fail_on=Severity.HIGH))
        assert not r.passed

    def test_fail_on_high_passes_on_medium(self):
        r = evaluate_gate([_f(severity=Severity.MEDIUM)], _score("B"),
                          GateConfig(fail_on=Severity.HIGH))
        assert r.passed

    def test_fail_on_critical_ignores_high(self):
        r = evaluate_gate([_f(severity=Severity.HIGH)], _score("B"),
                          GateConfig(fail_on=Severity.CRITICAL))
        assert r.passed

    def test_only_failing_findings_count(self):
        r = evaluate_gate(
            [_f(severity=Severity.CRITICAL, passed=True)],
            _score("A"),
            GateConfig(fail_on=Severity.HIGH),
        )
        assert r.passed


# ────────────────────────────────────────────────────────────────────────────
# --min-grade
# ────────────────────────────────────────────────────────────────────────────


class TestMinGrade:
    @pytest.mark.parametrize("actual,bar,passed", [
        ("A", "B", True),   # A is better than B → pass
        ("B", "B", True),   # equal → pass
        ("C", "B", False),  # worse → fail
        ("D", "A", False),
        ("A", "A", True),
    ])
    def test_grade_comparison(self, actual, bar, passed):
        r = evaluate_gate([_f()], _score(actual), GateConfig(min_grade=bar))
        assert r.passed is passed

    def test_unknown_grade_fails(self):
        r = evaluate_gate([_f()], _score("F"), GateConfig(min_grade="C"))
        assert not r.passed


# ────────────────────────────────────────────────────────────────────────────
# --max-failures
# ────────────────────────────────────────────────────────────────────────────


class TestMaxFailures:
    def test_exactly_at_cap_passes(self):
        findings = [_f(resource=f"r{i}") for i in range(3)]
        r = evaluate_gate(findings, _score("B"), GateConfig(max_failures=3))
        assert r.passed

    def test_over_cap_fails(self):
        findings = [_f(resource=f"r{i}") for i in range(4)]
        r = evaluate_gate(findings, _score("B"), GateConfig(max_failures=3))
        assert not r.passed

    def test_zero_tolerance(self):
        r = evaluate_gate([_f()], _score("A"), GateConfig(max_failures=0))
        assert not r.passed


# ────────────────────────────────────────────────────────────────────────────
# --fail-on-check
# ────────────────────────────────────────────────────────────────────────────


class TestFailOnCheck:
    def test_named_check_fails(self):
        r = evaluate_gate(
            [_f(check_id="IAM-001"), _f(check_id="CB-003")],
            _score("B"),
            GateConfig(fail_on_checks={"IAM-001"}),
        )
        assert not r.passed
        assert "IAM-001" in r.reasons[0]

    def test_unnamed_check_passes_gate(self):
        r = evaluate_gate(
            [_f(check_id="CB-003")],
            _score("B"),
            GateConfig(fail_on_checks={"IAM-001"}),
        )
        assert r.passed

    def test_case_insensitive(self):
        r = evaluate_gate(
            [_f(check_id="iam-001")],
            _score("B"),
            GateConfig(fail_on_checks={"IAM-001"}),
        )
        assert not r.passed


# ────────────────────────────────────────────────────────────────────────────
# Baseline diff
# ────────────────────────────────────────────────────────────────────────────


class TestBaseline:
    def test_baseline_suppresses_preexisting_finding(self, tmp_path):
        baseline = {
            "findings": [
                {"check_id": "CB-001", "resource": "proj-a", "passed": False},
            ]
        }
        p = tmp_path / "baseline.json"
        p.write_text(json.dumps(baseline))
        cfg = GateConfig(
            baseline_path=str(p), fail_on=Severity.HIGH,
        )
        # Same finding still present in current run — should be baseline-matched.
        r = evaluate_gate([_f()], _score("B"), cfg)
        assert r.passed
        assert len(r.baseline_matched) == 1
        assert len(r.effective) == 0

    def test_baseline_does_not_suppress_new_finding(self, tmp_path):
        baseline = {
            "findings": [
                {"check_id": "CB-001", "resource": "proj-a", "passed": False},
            ]
        }
        p = tmp_path / "baseline.json"
        p.write_text(json.dumps(baseline))
        cfg = GateConfig(baseline_path=str(p), fail_on=Severity.HIGH)
        new = _f(check_id="IAM-001", resource="role-x")
        r = evaluate_gate([_f(), new], _score("B"), cfg)
        assert not r.passed
        assert len(r.baseline_matched) == 1
        assert len(r.effective) == 1
        assert r.effective[0].check_id == "IAM-001"

    def test_baseline_distinguishes_by_resource(self, tmp_path):
        baseline = {
            "findings": [
                {"check_id": "CB-001", "resource": "proj-a", "passed": False},
            ]
        }
        p = tmp_path / "baseline.json"
        p.write_text(json.dumps(baseline))
        cfg = GateConfig(baseline_path=str(p), fail_on=Severity.HIGH)
        # Same check but different resource → not in baseline.
        r = evaluate_gate([_f(resource="proj-b")], _score("B"), cfg)
        assert not r.passed
        assert r.baseline_matched == []

    def test_missing_baseline_file_is_empty(self, tmp_path):
        assert load_baseline(tmp_path / "nope.json") == set()

    def test_malformed_baseline_is_empty(self, tmp_path):
        p = tmp_path / "b.json"
        p.write_text("not json")
        assert load_baseline(p) == set()

    def test_baseline_only_includes_failed_findings(self, tmp_path):
        """Passed findings in the baseline must not suppress current failures."""
        baseline = {
            "findings": [
                {"check_id": "CB-001", "resource": "proj-a", "passed": True},
            ]
        }
        p = tmp_path / "b.json"
        p.write_text(json.dumps(baseline))
        cfg = GateConfig(baseline_path=str(p), fail_on=Severity.HIGH)
        r = evaluate_gate([_f()], _score("B"), cfg)
        assert not r.passed


# ────────────────────────────────────────────────────────────────────────────
# Ignore file
# ────────────────────────────────────────────────────────────────────────────


class TestIgnoreFile:
    def test_check_id_only_suppresses_everywhere(self):
        cfg = GateConfig(
            fail_on=Severity.HIGH,
            ignore_rules=[IgnoreRule(check_id="CB-001", resource=None)],
        )
        r = evaluate_gate(
            [_f(check_id="CB-001", resource="a"),
             _f(check_id="CB-001", resource="b")],
            _score("B"),
            cfg,
        )
        assert r.passed
        assert len(r.suppressed) == 2

    def test_resource_scoped_rule(self):
        cfg = GateConfig(
            fail_on=Severity.HIGH,
            ignore_rules=[IgnoreRule(check_id="CB-001", resource="proj-a")],
        )
        r = evaluate_gate(
            [_f(resource="proj-a"), _f(resource="proj-b")],
            _score("B"),
            cfg,
        )
        assert not r.passed
        assert len(r.suppressed) == 1
        assert len(r.effective) == 1
        assert r.effective[0].resource == "proj-b"

    def test_load_ignore_file_parses_lines(self, tmp_path):
        p = tmp_path / ".pipelinecheckignore"
        p.write_text(
            "# a comment\n"
            "CB-001\n"
            "IAM-002:my-role   # trailing comment\n"
            "\n"
            "   \n"
            "gha-001:.github/workflows/legacy.yml\n"
        )
        rules = load_ignore_file(p)
        assert IgnoreRule(check_id="CB-001", resource=None) in rules
        assert IgnoreRule(check_id="IAM-002", resource="my-role") in rules
        assert IgnoreRule(
            check_id="GHA-001",
            resource=".github/workflows/legacy.yml",
        ) in rules
        assert len(rules) == 3

    def test_load_missing_ignore_returns_empty(self, tmp_path):
        assert load_ignore_file(tmp_path / "nope") == []


# ────────────────────────────────────────────────────────────────────────────
# Interactions
# ────────────────────────────────────────────────────────────────────────────


class TestInteractions:
    def test_baseline_and_ignore_combine(self, tmp_path):
        baseline = {
            "findings": [
                {"check_id": "CB-001", "resource": "proj-a", "passed": False},
            ]
        }
        p = tmp_path / "b.json"
        p.write_text(json.dumps(baseline))
        cfg = GateConfig(
            fail_on=Severity.HIGH,
            baseline_path=str(p),
            ignore_rules=[IgnoreRule(check_id="IAM-001", resource=None)],
        )
        r = evaluate_gate(
            [
                _f(check_id="CB-001", resource="proj-a"),    # baseline
                _f(check_id="IAM-001", resource="role-x"),   # ignored
                _f(check_id="CP-002", resource="pipe-1"),    # effective
            ],
            _score("B"),
            cfg,
        )
        assert not r.passed
        assert len(r.baseline_matched) == 1
        assert len(r.suppressed) == 1
        assert len(r.effective) == 1
        assert r.effective[0].check_id == "CP-002"

    def test_multiple_conditions_accumulate_reasons(self):
        cfg = GateConfig(
            fail_on=Severity.HIGH,
            max_failures=0,
            fail_on_checks={"CB-001"},
        )
        r = evaluate_gate([_f()], _score("A"), cfg)
        assert not r.passed
        # All three conditions trip on the same single finding.
        assert len(r.reasons) == 3

    def test_baseline_suppresses_critical_against_default_gate(self, tmp_path):
        """A baseline-matched CRITICAL is not in the effective set and
        therefore does not trip the default --fail-on CRITICAL gate."""
        baseline = {
            "findings": [
                {"check_id": "CB-001", "resource": "proj-a", "passed": False},
            ]
        }
        p = tmp_path / "b.json"
        p.write_text(json.dumps(baseline))
        cfg = GateConfig(baseline_path=str(p))
        r = evaluate_gate(
            [_f(severity=Severity.CRITICAL)], _score("A"), cfg,
        )
        assert r.passed

    def test_any_explicit_gate_detection(self):
        assert GateConfig().any_explicit_gate() is False
        assert GateConfig(fail_on=Severity.HIGH).any_explicit_gate() is True
        assert GateConfig(min_grade="B").any_explicit_gate() is True
        assert GateConfig(max_failures=0).any_explicit_gate() is True
        assert GateConfig(fail_on_checks={"X"}).any_explicit_gate() is True


# ────────────────────────────────────────────────────────────────────────────
# CLI integration
# ────────────────────────────────────────────────────────────────────────────


class TestCliIntegration:
    def _setup_wf(self, tmp_path):
        wf = tmp_path / "wf"
        wf.mkdir()
        (wf / "c.yml").write_text(
            "on: push\n"
            "jobs:\n"
            "  b:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"  # GHA-001 will fail (tag not SHA)
        )
        return wf

    def test_fail_on_high_trips_exit_1(self, tmp_path):
        from click.testing import CliRunner

        from pipeline_check.cli import scan

        wf = self._setup_wf(tmp_path)
        r = CliRunner().invoke(scan, [
            "--pipeline", "github", "--gha-path", str(wf),
            "--fail-on", "HIGH", "--output", "json",
        ])
        assert r.exit_code == 1

    def test_fail_on_critical_passes_on_high_only(self, tmp_path):
        from click.testing import CliRunner

        from pipeline_check.cli import scan

        wf = self._setup_wf(tmp_path)
        r = CliRunner().invoke(scan, [
            "--pipeline", "github", "--gha-path", str(wf),
            "--fail-on", "CRITICAL", "--output", "json",
        ])
        assert r.exit_code == 0

    def test_ignore_file_suppresses_gate(self, tmp_path):
        from click.testing import CliRunner

        from pipeline_check.cli import scan

        wf = self._setup_wf(tmp_path)
        ignore = tmp_path / "ig"
        ignore.write_text("GHA-001\n")
        r = CliRunner().invoke(scan, [
            "--pipeline", "github", "--gha-path", str(wf),
            "--fail-on", "HIGH",
            "--ignore-file", str(ignore),
            "--output", "json",
        ])
        assert r.exit_code == 0

    def test_baseline_suppresses_preexisting(self, tmp_path):
        from click.testing import CliRunner

        from pipeline_check.cli import scan

        wf = self._setup_wf(tmp_path)
        # First run → capture baseline JSON.
        first = CliRunner().invoke(scan, [
            "--pipeline", "github", "--gha-path", str(wf),
            "--output", "json",
        ])
        baseline = tmp_path / "baseline.json"
        baseline.write_text(first.stdout)

        # Second run with same fixture + baseline → gate should pass.
        r = CliRunner().invoke(scan, [
            "--pipeline", "github", "--gha-path", str(wf),
            "--fail-on", "HIGH",
            "--baseline", str(baseline),
            "--output", "json",
        ])
        assert r.exit_code == 0
