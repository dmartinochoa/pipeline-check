"""CLI ease-of-use tests — auto-detect, grouped help, init, short flags, hints."""
from __future__ import annotations

from unittest.mock import patch

import pytest
from click.testing import CliRunner

from pipeline_check.cli import (
    _detect_pipeline_from_cwd,
    init_cmd,
    main,
    scan,
)
from pipeline_check.core.checks.base import Finding, Severity
from pipeline_check.core.scanner import ScanMetadata


@pytest.fixture
def runner():
    return CliRunner()


def _mock_meta():
    return ScanMetadata(
        provider="aws",
        files_scanned=0,
        files_skipped=0,
        elapsed_seconds=0.0,
        warnings=[],
    )


# ── auto-detect ─────────────────────────────────────────────────────────────


class TestAutoDetect:
    def test_detects_github(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".github" / "workflows").mkdir(parents=True)
        assert _detect_pipeline_from_cwd() == "github"

    def test_detects_gitlab(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".gitlab-ci.yml").write_text("stages: []\n")
        assert _detect_pipeline_from_cwd() == "gitlab"

    def test_detects_jenkins(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "Jenkinsfile").write_text("pipeline {}\n")
        assert _detect_pipeline_from_cwd() == "jenkins"

    def test_detects_cloudbuild(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "cloudbuild.yaml").write_text("steps: []\n")
        assert _detect_pipeline_from_cwd() == "cloudbuild"

    def test_detects_cloudformation(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "template.yml").write_text("Resources: {}\n")
        assert _detect_pipeline_from_cwd() == "cloudformation"

    def test_returns_none_for_empty_dir(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        assert _detect_pipeline_from_cwd() is None

    def test_scan_resolves_auto_to_detected(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".gitlab-ci.yml").write_text("stages: []\n")
        with patch("pipeline_check.cli.Scanner") as MS:
            MS.return_value.run.return_value = []
            MS.return_value.metadata = _mock_meta()
            MS.return_value.inventory.return_value = []
            result = runner.invoke(scan, [])
        assert result.exit_code == 0
        assert "[auto] detected --pipeline gitlab" in result.stderr
        assert MS.call_args.kwargs["pipeline"] == "gitlab"

    def test_scan_auto_falls_back_to_aws(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        with patch("pipeline_check.cli.Scanner") as MS:
            MS.return_value.run.return_value = []
            MS.return_value.metadata = _mock_meta()
            result = runner.invoke(scan, [])
        assert result.exit_code == 0
        assert "no CI files found at cwd; using --pipeline aws" in result.stderr
        assert MS.call_args.kwargs["pipeline"] == "aws"


# ── grouped help ────────────────────────────────────────────────────────────


class TestGroupedHelp:
    def test_help_has_sections(self, runner):
        result = runner.invoke(scan, ["--help"])
        assert result.exit_code == 0
        assert "Target:" in result.output
        assert "Filtering:" in result.output
        assert "Output:" in result.output
        assert "Gate:" in result.output
        assert "Autofix:" in result.output
        assert "Info & Help:" in result.output

    def test_help_keeps_every_flag(self, runner):
        result = runner.invoke(scan, ["--help"])
        # Spot-check representative flags from each section.
        for flag in (
            "--pipeline", "--target", "--region",
            "--checks", "--severity-threshold",
            "--output", "--inventory-only",
            "--fail-on", "--baseline", "--ignore-file",
            "--fix", "--apply",
            "--list-checks", "--man", "--config-check",
        ):
            assert flag in result.output, f"missing from --help: {flag}"


# ── init subcommand ─────────────────────────────────────────────────────────


class TestInit:
    def test_writes_scaffold(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(init_cmd, [])
        assert result.exit_code == 0
        target = tmp_path / ".pipeline-check.yml"
        assert target.exists()
        body = target.read_text()
        assert "gate:" in body
        assert "# pipeline:" in body  # no CI files → commented-out

    def test_prefills_detected_pipeline(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".gitlab-ci.yml").write_text("stages: []\n")
        result = runner.invoke(init_cmd, [])
        assert result.exit_code == 0
        body = (tmp_path / ".pipeline-check.yml").read_text()
        assert "pipeline: gitlab" in body

    def test_refuses_to_overwrite(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        target = tmp_path / ".pipeline-check.yml"
        target.write_text("# existing\n")
        result = runner.invoke(init_cmd, [])
        assert result.exit_code != 0
        assert "--force" in result.stderr
        assert target.read_text() == "# existing\n"

    def test_force_overwrites(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        target = tmp_path / ".pipeline-check.yml"
        target.write_text("# existing\n")
        result = runner.invoke(init_cmd, ["--force"])
        assert result.exit_code == 0
        assert "# existing" not in target.read_text()

    def test_custom_path(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(init_cmd, ["--path", "cfg/custom.yml"])
        # Directory doesn't exist — should surface a UsageError.
        assert result.exit_code != 0
        (tmp_path / "cfg").mkdir()
        result = runner.invoke(init_cmd, ["--path", "cfg/custom.yml"])
        assert result.exit_code == 0
        assert (tmp_path / "cfg" / "custom.yml").exists()

    def test_main_dispatch_routes_to_init(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr("sys.argv", ["pipeline_check", "init"])
        # main() invokes init_cmd which calls sys.exit on Click completion.
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code in (0, None)
        assert (tmp_path / ".pipeline-check.yml").exists()


# ── short flags ─────────────────────────────────────────────────────────────


class TestShortFlags:
    def test_short_pipeline_output(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        with patch("pipeline_check.cli.Scanner") as MS:
            MS.return_value.run.return_value = []
            MS.return_value.metadata = _mock_meta()
            result = runner.invoke(scan, ["-p", "aws", "-o", "json"])
        assert result.exit_code == 0
        assert MS.call_args.kwargs["pipeline"] == "aws"
        # JSON lands on stdout cleanly.
        assert result.stdout.strip().startswith("{")

    def test_short_fail_on_and_region(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        with patch("pipeline_check.cli.Scanner") as MS:
            MS.return_value.run.return_value = []
            MS.return_value.metadata = _mock_meta()
            result = runner.invoke(scan, ["-p", "aws", "-f", "HIGH", "-r", "eu-west-1"])
        assert result.exit_code == 0
        assert MS.call_args.kwargs["region"] == "eu-west-1"


# ── hints ───────────────────────────────────────────────────────────────────


class TestHints:
    def test_pipeline_typo_suggests_close_match(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(scan, ["--pipeline", "gitub"])
        assert result.exit_code != 0
        assert "Did you mean" in result.stderr
        assert "github" in result.stderr

    def test_wrong_provider_hint_fires_in_ci_repo(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".github" / "workflows").mkdir(parents=True)
        deg = Finding(
            check_id="CB-000", title="t", severity=Severity.INFO,
            resource="r", description="d", recommendation="rec", passed=True,
        )
        with patch("pipeline_check.cli.Scanner") as MS:
            MS.return_value.run.return_value = [deg]
            MS.return_value.metadata = _mock_meta()
            result = runner.invoke(scan, ["--pipeline", "aws"])
        assert "[hint]" in result.stderr
        assert "--pipeline github" in result.stderr

    def test_wrong_provider_hint_silent_on_real_findings(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".github" / "workflows").mkdir(parents=True)
        real = Finding(
            check_id="CB-003", title="t", severity=Severity.HIGH,
            resource="r", description="d", recommendation="rec", passed=False,
        )
        with patch("pipeline_check.cli.Scanner") as MS:
            MS.return_value.run.return_value = [real]
            MS.return_value.metadata = _mock_meta()
            result = runner.invoke(scan, ["--pipeline", "aws"])
        assert "[hint]" not in result.stderr
