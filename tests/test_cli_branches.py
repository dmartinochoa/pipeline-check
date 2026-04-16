"""Targeted CLI tests covering previously-uncovered branches.

These fill specific coverage gaps in ``pipeline_check/cli.py``:

- ``--list-standards`` early return
- Each provider's UsageError paths (missing flag, missing file)
- ``--output sarif --output-file`` write-to-disk branch
- Gate summary rendering on stderr for PASS/FAIL, baseline, and ignore
"""
from __future__ import annotations

import json
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from pipeline_check.cli import scan
from pipeline_check.core.checks.base import Finding, Severity


@pytest.fixture
def runner():
    return CliRunner()


def _finding(
    check_id="CB-001", severity=Severity.CRITICAL, passed=False, resource="r",
):
    return Finding(
        check_id=check_id,
        title="t",
        severity=severity,
        resource=resource,
        description="d",
        recommendation="rec",
        passed=passed,
    )


class TestListStandards:
    def test_prints_every_registered_standard(self, runner):
        result = runner.invoke(scan, ["--list-standards"])
        assert result.exit_code == 0
        assert "owasp_cicd_top_10" in result.output
        assert "cis_aws_foundations" in result.output
        assert "slsa" in result.output
        # URLs should render too
        assert "https://owasp.org/www-project-top-10-ci-cd-security-risks/" in result.output


class TestProviderUsageErrors:
    def test_terraform_missing_flag(self, runner):
        result = runner.invoke(scan, ["--pipeline", "terraform"])
        assert result.exit_code != 0
        assert "tf-plan" in result.output

    def test_terraform_missing_file(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(scan, [
            "--pipeline", "terraform", "--tf-plan", "nope.json",
        ])
        assert result.exit_code != 0
        assert "not found" in result.output.lower()

    def test_github_missing_dir_flag(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(scan, [
            "--pipeline", "github", "--gha-path", "does-not-exist",
        ])
        assert result.exit_code != 0
        assert "not found" in result.output.lower()

    def test_bitbucket_missing_file_no_flag(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(scan, ["--pipeline", "bitbucket"])
        assert result.exit_code != 0
        assert "bitbucket-path" in result.output.lower()

    def test_azure_missing_file_no_flag(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(scan, ["--pipeline", "azure"])
        assert result.exit_code != 0
        assert "azure-path" in result.output.lower()

    def test_azure_missing_file_with_bad_flag(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(scan, [
            "--pipeline", "azure", "--azure-path", "does-not-exist.yml",
        ])
        assert result.exit_code != 0
        assert "not found" in result.output.lower()


class TestSarifOutputFile:
    def test_sarif_to_file_writes_and_reports_path(self, runner, tmp_path):
        out = tmp_path / "report.sarif"
        with patch("pipeline_check.cli.Scanner") as MockScanner:
            MockScanner.return_value.run.return_value = [_finding()]
            result = runner.invoke(scan, [
                "--output", "sarif", "--output-file", str(out),
            ])
        # SARIF file should exist and parse.
        assert out.exists()
        payload = json.loads(out.read_text())
        assert payload["version"] == "2.1.0"
        # stderr message confirms write.
        err = result.stderr if hasattr(result, "stderr") else result.output
        assert "SARIF report written" in (result.output + err)


class TestGateSummary:
    def test_fail_message_on_stderr(self, runner):
        """CRITICAL finding + default gate → stderr shows [gate] FAIL with reason."""
        with patch("pipeline_check.cli.Scanner") as MockScanner:
            MockScanner.return_value.run.return_value = [
                _finding(severity=Severity.CRITICAL),
            ]
            result = runner.invoke(scan, ["--output", "terminal"])
        assert result.exit_code == 1
        # In click 8's runner, stderr and stdout are combined unless
        # mix_stderr=False; either way the gate line lands in output.
        assert "[gate] FAIL" in result.output
        assert "default gate" in result.output

    def test_no_summary_when_clean(self, runner):
        """No failing findings → no [gate] line (gate passed silently)."""
        with patch("pipeline_check.cli.Scanner") as MockScanner:
            MockScanner.return_value.run.return_value = [
                _finding(passed=True, severity=Severity.CRITICAL),
            ]
            result = runner.invoke(scan, ["--output", "terminal"])
        assert result.exit_code == 0
        assert "[gate] FAIL" not in result.output

    def test_baseline_suppression_is_reported(self, runner, tmp_path):
        # Baseline contains the exact (check_id, resource) we'll emit.
        baseline = tmp_path / "b.json"
        baseline.write_text(json.dumps({
            "findings": [
                {"check_id": "CB-001", "resource": "r", "passed": False},
            ]
        }))
        with patch("pipeline_check.cli.Scanner") as MockScanner:
            MockScanner.return_value.run.return_value = [
                _finding(severity=Severity.CRITICAL),
            ]
            result = runner.invoke(scan, [
                "--output", "terminal",
                "--baseline", str(baseline),
            ])
        # Finding is baseline-matched, so gate passes; but the summary
        # still mentions the suppression count.
        assert result.exit_code == 0
        assert "suppressed by baseline" in result.output

    def test_ignore_file_suppression_is_reported(self, runner, tmp_path):
        ignore = tmp_path / "ig"
        ignore.write_text("CB-001\n")
        with patch("pipeline_check.cli.Scanner") as MockScanner:
            MockScanner.return_value.run.return_value = [
                _finding(severity=Severity.CRITICAL),
            ]
            result = runner.invoke(scan, [
                "--output", "terminal",
                "--ignore-file", str(ignore),
            ])
        assert result.exit_code == 0
        assert "suppressed by ignore file" in result.output

    def test_json_output_suppresses_gate_summary(self, runner):
        """JSON on stdout must stay parseable — gate summary is omitted."""
        with patch("pipeline_check.cli.Scanner") as MockScanner:
            MockScanner.return_value.run.return_value = [
                _finding(severity=Severity.CRITICAL),
            ]
            result = runner.invoke(scan, ["--output", "json"])
        # stdout must parse as JSON.
        payload = json.loads(result.stdout)
        assert "findings" in payload
        assert "[gate]" not in result.stdout


class TestScanFailure:
    def test_scanner_exception_exits_2(self, runner):
        with patch("pipeline_check.cli.Scanner") as MockScanner:
            MockScanner.return_value.run.side_effect = RuntimeError("boom")
            result = runner.invoke(scan, ["--output", "json"])
        assert result.exit_code == 2
        assert "boom" in result.output
