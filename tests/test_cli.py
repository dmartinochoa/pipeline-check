"""CLI integration tests — exit codes, output format, flag wiring."""

import json
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from pipeline_check.cli import scan
from pipeline_check.core.checks.base import Finding, Severity


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


@pytest.fixture
def runner():
    return CliRunner()


class TestExitCodes:
    def test_exit_0_on_passing_scan(self, runner):
        findings = [_finding(passed=True) for _ in range(5)]
        with patch("pipeline_check.cli.Scanner") as MockScanner:
            MockScanner.return_value.run.return_value = findings
            result = runner.invoke(scan, ["--output", "json"])
        assert result.exit_code == 0

    def test_exit_1_on_grade_d(self, runner):
        # 10 CRITICAL failures push score well below 60 → grade D
        findings = [
            _finding(passed=False, severity=Severity.CRITICAL)
            for _ in range(10)
        ]
        with patch("pipeline_check.cli.Scanner") as MockScanner:
            MockScanner.return_value.run.return_value = findings
            result = runner.invoke(scan, ["--output", "json"])
        assert result.exit_code == 1

    def test_exit_2_on_scan_exception(self, runner):
        with patch("pipeline_check.cli.Scanner") as MockScanner:
            MockScanner.return_value.run.side_effect = Exception("AWS API unreachable")
            result = runner.invoke(scan, ["--output", "json"])
        assert result.exit_code == 2


class TestJsonOutput:
    def test_output_is_valid_json(self, runner):
        with patch("pipeline_check.cli.Scanner") as MockScanner:
            MockScanner.return_value.run.return_value = [_finding()]
            result = runner.invoke(scan, ["--output", "json"])
        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert "score" in payload
        assert "findings" in payload

    def test_output_contains_all_findings(self, runner):
        findings = [_finding(check_id=f"CB-00{i}") for i in range(1, 4)]
        with patch("pipeline_check.cli.Scanner") as MockScanner:
            MockScanner.return_value.run.return_value = findings
            result = runner.invoke(scan, ["--output", "json"])
        payload = json.loads(result.output)
        assert len(payload["findings"]) == 3

    def test_score_fields_present(self, runner):
        with patch("pipeline_check.cli.Scanner") as MockScanner:
            MockScanner.return_value.run.return_value = [_finding()]
            result = runner.invoke(scan, ["--output", "json"])
        score = json.loads(result.output)["score"]
        assert "score" in score
        assert "grade" in score
        assert "summary" in score
        assert score["grade"] in ("A", "B", "C", "D")
        assert 0 <= score["score"] <= 100


class TestFlagWiring:
    def test_checks_filter_forwarded_to_scanner(self, runner):
        with patch("pipeline_check.cli.Scanner") as MockScanner:
            MockScanner.return_value.run.return_value = []
            runner.invoke(scan, ["--checks", "CB-001", "--checks", "CB-002", "--output", "json"])
        MockScanner.return_value.run.assert_called_once_with(
            checks=["CB-001", "CB-002"], target=None
        )

    def test_target_forwarded_to_scanner(self, runner):
        with patch("pipeline_check.cli.Scanner") as MockScanner:
            MockScanner.return_value.run.return_value = []
            runner.invoke(scan, ["--target", "my-pipeline", "--output", "json"])
        MockScanner.return_value.run.assert_called_once_with(
            checks=None, target="my-pipeline"
        )

    def test_no_checks_passes_none_to_scanner(self, runner):
        with patch("pipeline_check.cli.Scanner") as MockScanner:
            MockScanner.return_value.run.return_value = []
            runner.invoke(scan, ["--output", "json"])
        MockScanner.return_value.run.assert_called_once_with(checks=None, target=None)

    def test_html_output_writes_file(self, runner, tmp_path):
        out = tmp_path / "report.html"
        with patch("pipeline_check.cli.Scanner") as MockScanner:
            MockScanner.return_value.run.return_value = [_finding()]
            result = runner.invoke(
                scan, ["--output", "html", "--output-file", str(out)]
            )
        assert result.exit_code == 0
        assert out.exists()
        assert "<html" in out.read_text().lower()
