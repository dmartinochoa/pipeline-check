"""Unit tests for reporter.py."""

import json

from rich.console import Console

from pipelineguard.core.checks.base import Finding, Severity
from pipelineguard.core.reporter import report_json, report_terminal
from pipelineguard.core.scorer import score


def _f(check_id, severity, passed, resource="proj"):
    return Finding(
        check_id=check_id,
        title=f"Title {check_id}",
        severity=severity,
        resource=resource,
        description="desc",
        recommendation="rec",
        owasp_cicd="CICD-SEC-1",
        passed=passed,
    )


FINDINGS = [
    _f("CB-001", Severity.CRITICAL, False),
    _f("CB-002", Severity.HIGH, True),
    _f("CB-003", Severity.MEDIUM, False),
    _f("CB-004", Severity.LOW, True),
    _f("CB-005", Severity.INFO, True),
]


class TestReportJson:
    def test_structure(self):
        result = score(FINDINGS)
        output = report_json(FINDINGS, result)
        data = json.loads(output)
        assert "score" in data
        assert "findings" in data
        assert len(data["findings"]) == len(FINDINGS)

    def test_finding_fields(self):
        result = score(FINDINGS)
        output = report_json(FINDINGS, result)
        data = json.loads(output)
        f = data["findings"][0]
        for key in ("check_id", "title", "severity", "resource",
                    "description", "recommendation", "owasp_cicd", "passed"):
            assert key in f, f"Missing field: {key}"

    def test_severity_serialised_as_string(self):
        result = score(FINDINGS)
        output = report_json(FINDINGS, result)
        data = json.loads(output)
        severities = {f["severity"] for f in data["findings"]}
        assert all(isinstance(s, str) for s in severities)

    def test_score_keys(self):
        result = score(FINDINGS)
        output = report_json(FINDINGS, result)
        data = json.loads(output)
        assert "grade" in data["score"]
        assert "score" in data["score"]
        assert "summary" in data["score"]


class TestReportTerminal:
    """Smoke-tests for terminal reporter — verifies no exceptions are raised."""

    def _run(self, findings, threshold=Severity.INFO):
        console = Console(file=open("nul", "w") if False else __import__("io").StringIO(),
                          highlight=False)
        result = score(findings)
        report_terminal(findings, result, severity_threshold=threshold, console=console)

    def test_renders_without_error(self):
        self._run(FINDINGS)

    def test_renders_empty_findings(self):
        self._run([])

    def test_severity_threshold_filters(self):
        import io
        buf = io.StringIO()
        console = Console(file=buf, highlight=False, width=120)
        findings = [_f("CB-001", Severity.LOW, False)]
        result = score(findings)
        # Threshold = HIGH: LOW finding should not appear
        report_terminal(findings, result, severity_threshold=Severity.HIGH, console=console)
        output = buf.getvalue()
        assert "CB-001" not in output

    def test_severity_threshold_shows_matching(self):
        import io
        buf = io.StringIO()
        console = Console(file=buf, highlight=False, width=120)
        findings = [_f("CB-001", Severity.CRITICAL, False)]
        result = score(findings)
        report_terminal(findings, result, severity_threshold=Severity.HIGH, console=console)
        output = buf.getvalue()
        assert "CB-001" in output
