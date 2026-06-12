"""Tests for the advisory triage reporter and the CLI emit helper."""
from __future__ import annotations

from unittest.mock import patch

from pipeline_check.core.checks.base import Finding, Location, Severity
from pipeline_check.core.triage import TriageLabel, TriageVerdict
from pipeline_check.core.triage_reporter import report_triage


def _f(check_id="GHA-002", line=6, **kw):
    return Finding(
        check_id=check_id,
        title=kw.get("title", "t"),
        severity=Severity.HIGH,
        resource=kw.get("resource", ".github/workflows/ci.yml"),
        description="d",
        recommendation="r",
        passed=False,
        locations=(
            [Location(path=".github/workflows/ci.yml", start_line=line)]
            if line else []
        ),
    )


def _v(label, rationale=""):
    return TriageVerdict(label, rationale)


class TestReportTriage:
    def test_empty_is_blank(self):
        assert report_triage([], endpoint="e", model="m") == ""

    def test_header_carries_endpoint_and_model(self):
        out = report_triage(
            [(_f(), _v(TriageLabel.CONFIRMED))],
            endpoint="http://localhost:11434/api/generate", model="llama3.2",
        )
        assert "advisory" in out
        assert "http://localhost:11434/api/generate" in out
        assert "llama3.2" in out

    def test_line_per_finding_with_label_and_location(self):
        out = report_triage(
            [(_f(check_id="GHA-002", line=6), _v(TriageLabel.CONFIRMED, "reachable"))],
            endpoint="e", model="m",
        )
        assert "confirmed" in out
        assert "GHA-002" in out
        assert ".github/workflows/ci.yml:6" in out
        assert "reachable" in out

    def test_orders_confirmed_before_likely_fp_before_unavailable(self):
        results = [
            (_f(check_id="C-3"), _v(TriageLabel.UNAVAILABLE)),
            (_f(check_id="C-1"), _v(TriageLabel.CONFIRMED)),
            (_f(check_id="C-2"), _v(TriageLabel.LIKELY_FP)),
        ]
        out = report_triage(results, endpoint="e", model="m")
        assert out.index("C-1") < out.index("C-2") < out.index("C-3")

    def test_summary_counts(self):
        results = [
            (_f(check_id="A"), _v(TriageLabel.CONFIRMED)),
            (_f(check_id="B"), _v(TriageLabel.CONFIRMED)),
            (_f(check_id="C"), _v(TriageLabel.LIKELY_FP)),
        ]
        out = report_triage(results, endpoint="e", model="m")
        assert "2 confirmed" in out and "1 likely_fp" in out

    def test_location_falls_back_to_resource(self):
        out = report_triage(
            [(_f(line=0, resource="some/file.yml"), _v(TriageLabel.NEEDS_REVIEW))],
            endpoint="e", model="m",
        )
        assert "some/file.yml" in out


class TestEmitTriage:
    """The CLI helper that runs the pass and decides where to print."""

    def _run(self, *, output, output_file=None, findings=None, endpoint="http://localhost:11434/api/generate"):
        from pipeline_check.cli import _emit_triage
        findings = findings if findings is not None else [_f()]
        canned = [(findings[0], _v(TriageLabel.CONFIRMED, "yep"))]
        with patch(
            "pipeline_check.core.triage.triage_findings", return_value=canned,
        ):
            _emit_triage(
                findings, endpoint=endpoint, model="m",
                output=output, output_file=output_file, quiet=False,
            )

    def test_terminal_prints_section_to_stdout(self, capsys):
        self._run(output="terminal")
        out = capsys.readouterr()
        assert "LLM triage" in out.out and "confirmed" in out.out

    def test_machine_output_to_stdout_is_suppressed(self, capsys):
        self._run(output="json")
        cap = capsys.readouterr()
        assert "LLM triage" not in cap.out          # stdout stays clean
        assert "suppressed" in cap.err              # noted on stderr

    def test_machine_output_to_file_still_prints_section(self, capsys):
        self._run(output="sarif", output_file="scan.sarif")
        out = capsys.readouterr()
        assert "LLM triage" in out.out

    def test_non_local_endpoint_warns(self, capsys):
        self._run(output="terminal", endpoint="https://api.example.com/generate")
        err = capsys.readouterr().err
        assert "non-local endpoint" in err

    def test_no_failing_findings_notes_and_skips(self, capsys):
        from pipeline_check.cli import _emit_triage
        passing = Finding(
            check_id="OK", title="t", severity=Severity.LOW,
            resource="x", description="d", recommendation="r", passed=True,
        )
        _emit_triage(
            [passing], endpoint="http://localhost:11434/api/generate",
            model="m", output="terminal", output_file=None, quiet=False,
        )
        cap = capsys.readouterr()
        assert "no failing findings" in cap.err
