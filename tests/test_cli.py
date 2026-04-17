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

    def test_exit_1_on_any_critical(self, runner):
        # Default gate: --fail-on CRITICAL. A single CRITICAL finding fails.
        with patch("pipeline_check.cli.Scanner") as MockScanner:
            MockScanner.return_value.run.return_value = [
                _finding(passed=False, severity=Severity.CRITICAL),
            ]
            result = runner.invoke(scan, ["--output", "json"])
        assert result.exit_code == 1

    def test_exit_0_when_only_high_findings(self, runner):
        # Default gate no longer fails on grade alone — only on CRITICAL.
        findings = [
            _finding(passed=False, severity=Severity.HIGH) for _ in range(10)
        ]
        with patch("pipeline_check.cli.Scanner") as MockScanner:
            MockScanner.return_value.run.return_value = findings
            result = runner.invoke(scan, ["--output", "json"])
        assert result.exit_code == 0

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
        payload = json.loads(result.stdout)
        assert "score" in payload
        assert "findings" in payload

    def test_output_contains_all_findings(self, runner):
        findings = [_finding(check_id=f"CB-00{i}") for i in range(1, 4)]
        with patch("pipeline_check.cli.Scanner") as MockScanner:
            MockScanner.return_value.run.return_value = findings
            result = runner.invoke(scan, ["--output", "json"])
        payload = json.loads(result.stdout)
        assert len(payload["findings"]) == 3

    def test_score_fields_present(self, runner):
        with patch("pipeline_check.cli.Scanner") as MockScanner:
            MockScanner.return_value.run.return_value = [_finding()]
            result = runner.invoke(scan, ["--output", "json"])
        score = json.loads(result.stdout)["score"]
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
            checks=["CB-001", "CB-002"], target=None, standards=None
        )

    def test_target_forwarded_to_scanner(self, runner):
        with patch("pipeline_check.cli.Scanner") as MockScanner:
            MockScanner.return_value.run.return_value = []
            runner.invoke(scan, ["--target", "my-pipeline", "--output", "json"])
        MockScanner.return_value.run.assert_called_once_with(
            checks=None, target="my-pipeline", standards=None
        )

    def test_no_checks_passes_none_to_scanner(self, runner):
        with patch("pipeline_check.cli.Scanner") as MockScanner:
            MockScanner.return_value.run.return_value = []
            runner.invoke(scan, ["--output", "json"])
        MockScanner.return_value.run.assert_called_once_with(checks=None, target=None, standards=None)

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

    def test_html_output_requires_output_file(self, runner):
        with patch("pipeline_check.cli.Scanner") as MockScanner:
            MockScanner.return_value.run.return_value = [_finding()]
            result = runner.invoke(scan, ["--output", "html"])
        assert result.exit_code != 0
        assert "--output-file" in result.output or "--output-file" in (result.stderr or "")


class TestAutoDetect:
    def test_gitlab_path_autodetected(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".gitlab-ci.yml").write_text("build: {script: [make]}\n")
        result = runner.invoke(scan, ["--pipeline", "gitlab", "--output", "json"])
        assert result.exit_code in (0, 1), result.output
        # Auto-detection announced on stderr.
        assert "[auto] using --gitlab-path .gitlab-ci.yml" in result.output
        # Findings are from the GitLab provider (GL-001..005), proving the
        # resolved path was actually loaded and scanned.
        payload = json.loads(result.stdout)
        emitted = {f["check_id"] for f in payload["findings"]}
        assert emitted == {f"GL-{i:03d}" for i in range(1, 31)}

    def test_bitbucket_path_autodetected(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "bitbucket-pipelines.yml").write_text(
            "pipelines:\n  default:\n    - step: {script: [make]}\n"
        )
        result = runner.invoke(scan, ["--pipeline", "bitbucket", "--output", "json"])
        assert result.exit_code in (0, 1), result.output
        assert "[auto] using --bitbucket-path bitbucket-pipelines.yml" in result.output
        payload = json.loads(result.stdout)
        emitted = {f["check_id"] for f in payload["findings"]}
        assert emitted == {f"BB-{i:03d}" for i in range(1, 28)}


    def test_github_path_autodetected(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        (wf / "ci.yml").write_text(
            "on: push\njobs: {b: {runs-on: x, steps: [{run: echo}]}}\n"
        )
        result = runner.invoke(scan, ["--pipeline", "github", "--output", "json"])
        assert result.exit_code in (0, 1), result.output
        assert "[auto] using --gha-path" in result.output
        payload = json.loads(result.stdout)
        emitted = {f["check_id"] for f in payload["findings"]}
        assert emitted == {f"GHA-{i:03d}" for i in range(1, 30)}

    def test_gitlab_missing_file_raises_usage_error(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)  # no .gitlab-ci.yml present
        result = runner.invoke(scan, ["--pipeline", "gitlab", "--output", "json"])
        assert result.exit_code != 0
        assert "gitlab-path" in result.output.lower()
