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
def runner(tmp_path, monkeypatch):
    """Click test runner pinned to an isolated cwd with a minimal CI file.

    Since UX-3, empty cwd raises ``UsageError("no CI/CD config files
    detected")`` before the Scanner mock fires. Drop a trivial
    ``.gitlab-ci.yml`` so auto-detect resolves; the mocked Scanner
    intercepts the actual scan and these tests assert exit codes and
    output shape regardless of the picked provider.
    """
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".gitlab-ci.yml").write_text("stages: []\n")
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


class TestIncompleteScan:
    """A degraded scan (unparseable file, failed cloud probe) must not
    present as a confident pass. The terminal report flags the grade as
    incomplete and explains why."""

    def test_terminal_flags_unparseable_file(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        # Unbalanced bracket: YAML parse error, so no checks run on it.
        (wf / "bad.yml").write_text("on: [push\njobs:\n  b:\n")
        result = CliRunner().invoke(
            scan, ["--pipeline", "github", "--output", "terminal"]
        )
        out = result.output
        assert "incomplete scan:" in out
        assert "could not be parsed" in out
        # The grade carries the explicit tag rather than reading clean.
        assert "(incomplete)" in out

    def test_reason_helper(self):
        from types import SimpleNamespace

        from pipeline_check.cli import _scan_incomplete_reason

        # A parse-error warning marks the scan incomplete.
        meta = SimpleNamespace(warnings=["bad.yml: YAML parse error: ..."])
        assert "could not be parsed" in _scan_incomplete_reason(meta, [])

        # A degraded ``*-000`` cloud probe marks it incomplete too.
        degraded = _finding(check_id="IAM-000", passed=False)
        clean_meta = SimpleNamespace(warnings=[])
        reason = _scan_incomplete_reason(clean_meta, [degraded])
        assert reason is not None and "failed API access" in reason

        # A clean scan returns None (no banner).
        ok = _finding(check_id="CB-001", passed=True)
        assert _scan_incomplete_reason(SimpleNamespace(warnings=[]), [ok]) is None

    def test_status_helper_counts(self):
        from types import SimpleNamespace

        from pipeline_check.cli import _scan_status

        # A parse-error warning: incomplete, with counts and a reason.
        meta = SimpleNamespace(
            warnings=["bad.yml: YAML parse error: ..."], files_scanned=3,
        )
        status = _scan_status(meta, [])
        assert status["complete"] is False
        assert status["files_scanned"] == 3
        assert status["files_unparsed"] == 1
        assert status["degraded_modules"] == 0
        assert "could not be parsed" in status["reason"]
        # The raw warning strings ride along so a JSON/SARIF consumer sees
        # the same detail the stderr summary prints, not just the counts.
        assert status["warnings"] == ["bad.yml: YAML parse error: ..."]

        # A clean scan: complete, no reason key (consumers test `complete`),
        # and no ``warnings`` key when nothing warned (exact-dict below).
        ok = _finding(check_id="CB-001", passed=True)
        clean = _scan_status(SimpleNamespace(warnings=[], files_scanned=2), [ok])
        assert clean == {
            "complete": True, "files_scanned": 2,
            "files_unparsed": 0, "degraded_modules": 0,
        }

        # A degraded ``*-000`` probe counts as a degraded module.
        degraded = _finding(check_id="IAM-000", passed=False)
        d = _scan_status(SimpleNamespace(warnings=[], files_scanned=0), [degraded])
        assert d["degraded_modules"] == 1 and d["complete"] is False

    def test_json_emits_scan_status(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        (wf / "bad.yml").write_text("on: [push\njobs:\n  b:\n")
        out_file = tmp_path / "report.json"
        CliRunner().invoke(
            scan,
            ["--pipeline", "github", "--output", "json",
             "--output-file", str(out_file)],
        )
        data = json.loads(out_file.read_text())
        assert data["scan_status"]["complete"] is False
        assert data["scan_status"]["files_unparsed"] == 1

    def test_fail_on_parse_error_gate(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        (wf / "bad.yml").write_text("on: [push\njobs:\n  b:\n")
        args = ["--pipeline", "github", "--output", "terminal"]
        # Without the flag a parse failure is a warning, not a gate fail.
        assert CliRunner().invoke(scan, args).exit_code == 0
        # With it, the unparseable file trips the gate.
        result = CliRunner().invoke(scan, [*args, "--fail-on-parse-error"])
        assert result.exit_code == 1
        assert "could not be parsed" in result.output


class TestListStandards:
    def test_prints_every_registered_standard(self, runner):
        from pipeline_check.core import standards

        result = runner.invoke(scan, ["--list-standards"])
        assert result.exit_code == 0
        for name in standards.available():
            assert name in result.output, (
                f"--list-standards output missing {name!r}"
            )
        # URLs should render too
        assert "https://owasp.org/www-project-top-10-ci-cd-security-risks/" in result.output


class TestProviderUsageErrors:
    def test_terraform_missing_flag(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(scan, ["--pipeline", "terraform"])
        assert result.exit_code != 0
        # The error message may appear in output (UsageError) or in the
        # exception text (ValueError raised from build_context).
        combined = result.output + (str(result.exception) if result.exception else "")
        assert "tf-plan" in combined

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

    def test_grade_note_when_high_grade_fails_gate(self, runner):
        """Grade A/B sitting on a failing gate is the confusing case; the
        summary adds a note clarifying the grade is posture, not the gate."""
        findings = [
            _finding(check_id=f"CB-{i:03d}", passed=True) for i in range(1, 40)
        ]
        findings.append(
            _finding(check_id="CB-099", passed=False, severity=Severity.HIGH),
        )
        with patch("pipeline_check.cli.Scanner") as MockScanner:
            MockScanner.return_value.run.return_value = findings
            result = runner.invoke(
                scan, ["--output", "terminal", "--fail-on-check", "CB-099"],
            )
        assert result.exit_code == 1
        assert "[gate] FAIL" in result.output
        assert "[gate] note: Grade" in result.output
        assert "overall posture" in result.output

    def test_no_grade_note_when_grade_is_low(self, runner):
        """A low grade (C/D) failing the gate is unsurprising, so the
        clarifying note is suppressed."""
        with patch("pipeline_check.cli.Scanner") as MockScanner:
            MockScanner.return_value.run.return_value = [
                _finding(severity=Severity.CRITICAL),  # one CRITICAL fail → grade D
            ]
            result = runner.invoke(scan, ["--output", "terminal"])
        assert result.exit_code == 1
        assert "[gate] FAIL" in result.output
        assert "[gate] note: Grade" not in result.output

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


class TestGateTrailerAutofixTier:
    """The gate "what next" trailer must point at the fixer tier that will
    actually write changes: bare ``--fix`` is safe-only, so an unsafe-only
    failing set needs ``--fix unsafe --apply`` (the terminal report footer
    already does this; the gate trailer now matches)."""

    def test_unsafe_only_trailer_suggests_unsafe_tier(self):
        from types import SimpleNamespace

        from pipeline_check.cli import _build_gate_trailer
        from pipeline_check.core import autofix

        assert autofix.fixer_safety("GHA-003") == "unsafe"  # precondition
        gate = SimpleNamespace(effective=[_finding(check_id="GHA-003")])
        trailer = _build_gate_trailer(
            gate, baseline_path=None, baseline_from_git=None,
        )
        assert trailer is not None
        assert "--fix unsafe --apply" in trailer

    def test_safe_trailer_suggests_bare_fix(self):
        from types import SimpleNamespace

        from pipeline_check.cli import _build_gate_trailer
        from pipeline_check.core import autofix

        assert autofix.fixer_safety("GHA-001") == "safe"  # precondition
        gate = SimpleNamespace(effective=[_finding(check_id="GHA-001")])
        trailer = _build_gate_trailer(
            gate, baseline_path=None, baseline_from_git=None,
        )
        assert trailer is not None
        assert "--fix --apply" in trailer
        assert "--fix unsafe --apply" not in trailer

    def test_mixed_trailer_counts_safe_and_notes_unsafe(self):
        from types import SimpleNamespace

        from pipeline_check.cli import _build_gate_trailer

        gate = SimpleNamespace(effective=[
            _finding(check_id="GHA-001"),  # safe fixer
            _finding(check_id="GHA-003"),  # unsafe fixer
        ])
        trailer = _build_gate_trailer(
            gate, baseline_path=None, baseline_from_git=None,
        )
        assert trailer is not None
        assert "1 of 2" in trailer  # only the safe one applies with bare --fix
        assert "--fix unsafe --apply" in trailer
