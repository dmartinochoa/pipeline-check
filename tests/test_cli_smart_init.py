"""End-to-end CLI tests for the smart-init / explain / --no-group /
gate-trailer UX improvements.

These complement the unit tests in tests/test_init_scan.py (pure
functions) and tests/test_init_template.py (template surface). Here we
exercise the actual click commands via CliRunner so the integration of
flag parsing, scanner dispatch, baseline write, and stderr output is
covered end-to-end.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest
from click.testing import CliRunner

from pipeline_check.cli import (
    _build_gate_trailer,
    explain_cmd,
    init_cmd,
    scan,
)
from pipeline_check.core.checks.base import Finding, Location, Severity
from pipeline_check.core.gate import GateResult
from pipeline_check.core.scanner import ScanMetadata


@pytest.fixture
def runner():
    return CliRunner()


def _mock_meta():
    return ScanMetadata(
        provider="github",
        files_scanned=1,
        files_skipped=0,
        elapsed_seconds=0.0,
        warnings=[],
    )


# ── init: smart path ─────────────────────────────────────────────────────


class TestSmartInit:
    def test_smart_init_writes_baseline_and_tuned_gate(
        self, runner, tmp_path, monkeypatch
    ):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".github" / "workflows").mkdir(parents=True)
        failing = [
            Finding(
                check_id="GHA-001",
                title="Unpinned action",
                severity=Severity.HIGH,
                resource=".github/workflows/ci.yml",
                description="d",
                recommendation="rec",
                passed=False,
            ),
        ]
        with patch("pipeline_check.cli_ops_commands.Scanner") as MS:
            MS.return_value.run.return_value = failing
            MS.return_value.metadata = _mock_meta()
            result = runner.invoke(init_cmd, [])
        assert result.exit_code == 0
        cfg = (tmp_path / ".pipeline-check.yml").read_text()
        # Pipeline pre-filled from detect.
        assert "pipeline: github" in cfg
        # Tuned gate is written (Grade D, no critical → HIGH).
        assert "fail_on: HIGH" in cfg
        # Baseline file written and referenced.
        baseline = tmp_path / ".pipeline-check-baseline.json"
        assert baseline.exists()
        assert ".pipeline-check-baseline.json" in cfg
        # Summary lands on stderr.
        assert "[init] top to fix first:" in result.stderr
        assert "GHA-001" in result.stderr

    def test_smart_init_skips_baseline_when_no_failures(
        self, runner, tmp_path, monkeypatch
    ):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".github" / "workflows").mkdir(parents=True)
        passing = [
            Finding(
                check_id="GHA-001",
                title="Unpinned action",
                severity=Severity.HIGH,
                resource=".github/workflows/ci.yml",
                description="d",
                recommendation="rec",
                passed=True,
            ),
        ]
        with patch("pipeline_check.cli_ops_commands.Scanner") as MS:
            MS.return_value.run.return_value = passing
            MS.return_value.metadata = _mock_meta()
            result = runner.invoke(init_cmd, [])
        assert result.exit_code == 0
        cfg = (tmp_path / ".pipeline-check.yml").read_text()
        # Baseline line is commented out, no file written.
        assert "# baseline: " in cfg
        assert not (tmp_path / ".pipeline-check-baseline.json").exists()
        # MEDIUM gate (Grade A, clean scan).
        assert "fail_on: MEDIUM" in cfg

    def test_no_scan_falls_back_to_static_scaffold(
        self, runner, tmp_path, monkeypatch
    ):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".github" / "workflows").mkdir(parents=True)
        with patch("pipeline_check.cli_ops_commands.Scanner") as MS:
            result = runner.invoke(init_cmd, ["--no-scan"])
        assert result.exit_code == 0
        # Scanner never invoked.
        MS.assert_not_called()
        cfg = (tmp_path / ".pipeline-check.yml").read_text()
        # Tuned-gate (uncommented) line is absent; commented placeholder
        # gate key is present. The static scaffold leaves the gate
        # block entirely commented.
        assert "  fail_on: HIGH" not in cfg
        assert "# fail_on: HIGH" in cfg

    def test_no_pipeline_detected_falls_back_to_scaffold(
        self, runner, tmp_path, monkeypatch
    ):
        monkeypatch.chdir(tmp_path)
        with patch("pipeline_check.cli_ops_commands.Scanner") as MS:
            result = runner.invoke(init_cmd, [])
        assert result.exit_code == 0
        MS.assert_not_called()
        cfg = (tmp_path / ".pipeline-check.yml").read_text()
        assert "# pipeline:" in cfg

    def test_scan_failure_writes_static_scaffold(
        self, runner, tmp_path, monkeypatch
    ):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".github" / "workflows").mkdir(parents=True)
        with patch("pipeline_check.cli_ops_commands.Scanner") as MS:
            MS.side_effect = RuntimeError("boom")
            result = runner.invoke(init_cmd, [])
        assert result.exit_code == 0
        # Scaffold still written despite scan failure.
        cfg = (tmp_path / ".pipeline-check.yml").read_text()
        assert "pipeline: github" in cfg
        assert "scan failed" in result.stderr


# ── explain subcommand ──────────────────────────────────────────────────


class TestExplainCommand:
    def test_explain_known_check(self, runner):
        result = runner.invoke(explain_cmd, ["GHA-001"])
        assert result.exit_code == 0
        # The deterministic explain body always names the check ID.
        assert "GHA-001" in result.stdout

    def test_explain_unknown_check_returns_3_with_suggestions(self, runner):
        result = runner.invoke(explain_cmd, ["GHA-9999"])
        assert result.exit_code == 3
        assert "Unknown check" in result.stdout
        # Suggests near-matches sharing the GHA- prefix.
        assert "Did you mean" in result.stdout

    def test_explain_requires_argument(self, runner):
        result = runner.invoke(explain_cmd, [])
        assert result.exit_code != 0
        assert "missing CHECK_ID" in result.stderr


# ── --no-group flag ─────────────────────────────────────────────────────


class TestNoGroupFlag:
    def _two_dupes(self):
        # Same check_id + resource, different line numbers — the
        # grouping target. Default (group_similar=True) should render
        # one visible row plus a "+1 more" follower.
        return [
            Finding(
                check_id="GHA-001",
                title="Unpinned action",
                severity=Severity.HIGH,
                resource=".github/workflows/ci.yml",
                description="d",
                recommendation="rec",
                passed=False,
                locations=[Location(path=".github/workflows/ci.yml",
                                    start_line=10)],
            ),
            Finding(
                check_id="GHA-001",
                title="Unpinned action",
                severity=Severity.HIGH,
                resource=".github/workflows/ci.yml",
                description="d",
                recommendation="rec",
                passed=False,
                locations=[Location(path=".github/workflows/ci.yml",
                                    start_line=22)],
            ),
        ]

    def test_default_groups_repeated_findings(
        self, runner, tmp_path, monkeypatch
    ):
        monkeypatch.chdir(tmp_path)
        # Wide terminal so Rich's table column doesn't truncate the
        # follower-summary cell on 80-col defaults.
        monkeypatch.setenv("COLUMNS", "240")
        (tmp_path / ".github" / "workflows").mkdir(parents=True)
        with patch("pipeline_check.cli.Scanner") as MS:
            MS.return_value.run.return_value = self._two_dupes()
            MS.return_value.metadata = _mock_meta()
            result = runner.invoke(scan, ["-p", "github", "--fail-on", "LOW"])
        # Follower row signals grouping.
        assert "more on lines" in result.output

    def test_no_group_renders_every_row(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("COLUMNS", "240")
        (tmp_path / ".github" / "workflows").mkdir(parents=True)
        with patch("pipeline_check.cli.Scanner") as MS:
            MS.return_value.run.return_value = self._two_dupes()
            MS.return_value.metadata = _mock_meta()
            result = runner.invoke(
                scan, ["-p", "github", "--fail-on", "LOW", "--no-group"]
            )
        # No follower-row hint when grouping is off.
        assert "more on lines" not in result.output


# ── gate-failure trailer ────────────────────────────────────────────────


class TestGateTrailer:
    def _failing_finding(self, check_id: str = "GHA-001") -> Finding:
        return Finding(
            check_id=check_id,
            title="Unpinned action",
            severity=Severity.HIGH,
            resource=".github/workflows/ci.yml",
            description="d",
            recommendation="rec",
            passed=False,
        )

    def _gate(self, effective: list[Finding]) -> GateResult:
        return GateResult(
            passed=False,
            reasons=["1 finding"],
            effective=effective,
            suppressed=[],
            baseline_matched=[],
        )

    def test_trailer_suggests_autofix_when_available(self):
        # Pick a check we know has an autofixer registered.
        from pipeline_check.core.autofix import available_fixers
        any_fixer = next(iter(available_fixers()))
        f = self._failing_finding(check_id=any_fixer)
        text = _build_gate_trailer(
            self._gate([f]), baseline_path=None, baseline_from_git=None,
        )
        assert text is not None
        assert "autofix" in text
        assert "--fix --apply" in text

    def test_trailer_suggests_baseline_when_none_configured(self):
        # A finding with no registered fixer + no baseline → suggest
        # baseline so the team can start gating only on new findings.
        f = self._failing_finding(check_id="ZZZ-9999")
        text = _build_gate_trailer(
            self._gate([f]), baseline_path=None, baseline_from_git=None,
        )
        assert text is not None
        assert "--write-baseline" in text

    def test_trailer_suggests_explain_when_already_baselined(self):
        # No fixer, baseline already configured → tell user the next
        # move is `explain <ID>` for the worst rule.
        f = self._failing_finding(check_id="ZZZ-9999")
        text = _build_gate_trailer(
            self._gate([f]),
            baseline_path="baseline.json",
            baseline_from_git=None,
        )
        assert text is not None
        assert "explain ZZZ-9999" in text

    def test_trailer_silent_when_effective_set_is_empty(self):
        # A gate can fail on chain conditions with zero effective
        # findings. Nothing to suggest, so don't emit a misleading line.
        text = _build_gate_trailer(
            self._gate([]), baseline_path=None, baseline_from_git=None,
        )
        assert text is None
