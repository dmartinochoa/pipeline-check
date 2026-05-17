"""Unit tests for reporter.py."""

import json

from rich.console import Console

from pipeline_check.core.checks.base import Finding, Severity
from pipeline_check.core.reporter import report_json, report_terminal
from pipeline_check.core.scorer import score
from pipeline_check.core.standards.base import ControlRef


def _f(check_id, severity, passed, resource="proj"):
    return Finding(
        check_id=check_id,
        title=f"Title {check_id}",
        severity=severity,
        resource=resource,
        description="desc",
        recommendation="rec",
        passed=passed,
        controls=[ControlRef(
            standard="owasp_cicd_top_10",
            standard_title="OWASP Top 10 CI/CD Security Risks",
            control_id="CICD-SEC-1",
            control_title="Insufficient Flow Control Mechanisms",
        )],
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
                    "description", "recommendation", "controls", "passed"):
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

    def test_passed_findings_hidden_by_default(self):
        # Default UX: the table shows only failures. Passed checks
        # would drown a 50-rule scan on a 10-workflow repo in green
        # rows. The headline still reports the pass count.
        import io
        buf = io.StringIO()
        console = Console(file=buf, highlight=False, width=200)
        findings = [
            _f("CB-001", Severity.CRITICAL, False),
            _f("CB-002", Severity.HIGH, True),   # passed
            _f("CB-003", Severity.HIGH, True),   # passed
        ]
        report_terminal(findings, score(findings), console=console)
        output = buf.getvalue()
        assert "CB-001" in output
        # CB-002 / CB-003 passed — must not appear as table rows.
        assert "CB-002" not in output
        assert "CB-003" not in output

    def test_show_passed_brings_back_passes(self):
        import io
        buf = io.StringIO()
        console = Console(file=buf, highlight=False, width=200)
        findings = [
            _f("CB-001", Severity.CRITICAL, False),
            _f("CB-002", Severity.HIGH, True),
        ]
        report_terminal(
            findings, score(findings), console=console, show_passed=True,
        )
        output = buf.getvalue()
        assert "CB-001" in output
        assert "CB-002" in output

    def test_controls_hidden_by_default(self):
        # Compliance metadata always lands in JSON/SARIF; the terminal
        # default drops it to keep the per-finding panel scannable.
        import io
        buf = io.StringIO()
        console = Console(file=buf, highlight=False, width=200)
        findings = [_f("CB-001", Severity.CRITICAL, False)]
        report_terminal(findings, score(findings), console=console)
        output = buf.getvalue()
        # The OWASP control we attached must not surface in the panel.
        assert "Insufficient Flow Control" not in output

    def test_show_controls_renders_controls(self):
        import io
        buf = io.StringIO()
        console = Console(file=buf, highlight=False, width=200)
        findings = [_f("CB-001", Severity.CRITICAL, False)]
        report_terminal(
            findings, score(findings), console=console, show_controls=True,
        )
        output = buf.getvalue()
        assert "Insufficient Flow Control" in output

    def test_no_failures_hint_message(self):
        # When the threshold filters out every failure, surface a clear
        # hint instead of an empty table.
        import io
        buf = io.StringIO()
        console = Console(file=buf, highlight=False, width=200)
        findings = [_f("CB-001", Severity.LOW, False)]
        report_terminal(
            findings, score(findings),
            severity_threshold=Severity.HIGH, console=console,
        )
        output = buf.getvalue()
        assert "No failures at or above" in output
