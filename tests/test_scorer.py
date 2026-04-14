"""Unit tests for scorer.py — no mocking required."""

from pipelineguard.core.checks.base import Finding, Severity
from pipelineguard.core.scorer import score


def _finding(severity: Severity, passed: bool) -> Finding:
    return Finding(
        check_id="X-001",
        title="test",
        severity=severity,
        resource="res",
        description="",
        recommendation="",
        owasp_cicd="",
        passed=passed,
    )


class TestScore:
    def test_no_findings_returns_100_grade_a(self):
        result = score([])
        assert result["score"] == 100
        assert result["grade"] == "A"

    def test_all_pass_returns_100(self):
        findings = [
            _finding(Severity.CRITICAL, True),
            _finding(Severity.HIGH, True),
            _finding(Severity.MEDIUM, True),
        ]
        result = score(findings)
        assert result["score"] == 100
        assert result["grade"] == "A"

    def test_single_critical_failure_penalises_heavily(self):
        findings = [
            _finding(Severity.CRITICAL, False),
            _finding(Severity.LOW, True),
            _finding(Severity.LOW, True),
        ]
        result = score(findings)
        # CRITICAL fail = lose all CRITICAL weight + extra penalty; score must be < 75
        assert result["score"] < 75

    def test_grade_a_boundary(self):
        # 9 LOW passes + 0 failures => weight=18, passing=18 => raw=100
        findings = [_finding(Severity.LOW, True) for _ in range(9)]
        result = score(findings)
        assert result["grade"] == "A"
        assert result["score"] == 100

    def test_grade_d_below_60(self):
        findings = [
            _finding(Severity.CRITICAL, False),
            _finding(Severity.HIGH, False),
            _finding(Severity.HIGH, False),
        ]
        result = score(findings)
        assert result["grade"] == "D"
        assert result["score"] < 60

    def test_grade_boundaries(self):
        # Exactly all INFO findings — weight 0 — should be 100/A
        findings = [_finding(Severity.INFO, False) for _ in range(5)]
        result = score(findings)
        assert result["score"] == 100
        assert result["grade"] == "A"

    def test_summary_counts_correctly(self):
        findings = [
            _finding(Severity.CRITICAL, False),
            _finding(Severity.HIGH, True),
            _finding(Severity.HIGH, False),
            _finding(Severity.MEDIUM, True),
        ]
        result = score(findings)
        assert result["summary"]["CRITICAL"] == {"passed": 0, "failed": 1}
        assert result["summary"]["HIGH"] == {"passed": 1, "failed": 1}
        assert result["summary"]["MEDIUM"] == {"passed": 1, "failed": 0}
        assert result["summary"]["LOW"] == {"passed": 0, "failed": 0}

    def test_multiple_critical_failures_stack_penalty(self):
        findings = [_finding(Severity.CRITICAL, False) for _ in range(4)]
        result = score(findings)
        assert result["score"] == 0

    def test_score_clamped_to_zero(self):
        findings = [_finding(Severity.CRITICAL, False) for _ in range(20)]
        result = score(findings)
        assert result["score"] >= 0
