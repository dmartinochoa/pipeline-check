"""Tests for CLI UX improvements — scan summary, gate detail, config
announcement, autofix dry-run summary, and verbose flag.

Click 8.x CliRunner mixes stderr into ``result.output`` by default
(no ``mix_stderr`` parameter). All assertions that check for stderr
messages use ``result.output``, which is consistent with the existing
test_cli.py pattern.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest
from click.testing import CliRunner

from pipeline_check.cli import scan
from pipeline_check.core.checks.base import Finding, Severity
from pipeline_check.core.scanner import ScanMetadata


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


def _mock_scanner_with_metadata(findings, meta=None):
    """Patch Scanner so .run() returns *findings* and .metadata is *meta*."""
    if meta is None:
        meta = ScanMetadata(provider="github", files_scanned=3, elapsed_seconds=0.1)

    class FakeScanner:
        def __init__(self, **kw):
            self.metadata = meta
            self._check_classes = []

        def run(self, **kw):
            return findings

    return patch("pipeline_check.cli.Scanner", FakeScanner)


@pytest.fixture
def runner():
    return CliRunner()


# ────────────────────────────────────────────────────────────────────────────
# WU1: Scan summary + YAML parse warnings
# ────────────────────────────────────────────────────────────────────────────


class TestScanSummary:
    def test_summary_line_emitted(self, runner):
        with _mock_scanner_with_metadata([_finding()]):
            result = runner.invoke(scan, ["--output", "json"])
        assert "[scan] github: scanned 3 file(s) in" in result.output

    def test_summary_shows_skipped(self, runner):
        meta = ScanMetadata(
            provider="gitlab", files_scanned=2, files_skipped=1,
            elapsed_seconds=0.05,
        )
        with _mock_scanner_with_metadata([_finding()], meta):
            result = runner.invoke(scan, ["--output", "json"])
        assert "(1 skipped)" in result.output

    def test_warning_when_no_files(self, runner):
        meta = ScanMetadata(provider="github", files_scanned=0, files_skipped=0)
        with _mock_scanner_with_metadata([], meta):
            result = runner.invoke(scan, ["--output", "json"])
        assert "[warn] no pipeline files found to scan" in result.output

    def test_parse_warnings_emitted(self, runner):
        meta = ScanMetadata(
            provider="github", files_scanned=1, files_skipped=1,
            warnings=["broken.yml: YAML parse error: bad indent"],
        )
        with _mock_scanner_with_metadata([_finding()], meta):
            result = runner.invoke(scan, ["--output", "json"])
        assert "[warn] broken.yml: YAML parse error: bad indent" in result.output

    def test_quiet_suppresses_summary(self, runner):
        with _mock_scanner_with_metadata([_finding()]):
            result = runner.invoke(scan, ["--output", "json", "--quiet"])
        assert "[scan]" not in (result.output or "")
        assert "[warn]" not in (result.output or "")


class TestContextParseWarnings:
    """Integration tests: contexts populate warnings when given bad YAML."""

    def test_github_context_warns_on_bad_yaml(self, tmp_path):
        (tmp_path / "good.yml").write_text("name: ci\non: push\njobs: {}\n")
        (tmp_path / "bad.yml").write_text("key: [missing bracket\n")
        from pipeline_check.core.checks.github.base import GitHubContext
        ctx = GitHubContext.from_path(tmp_path)
        assert ctx.files_scanned == 1
        assert ctx.files_skipped == 1
        assert len(ctx.warnings) == 1
        assert "YAML parse error" in ctx.warnings[0]

    def test_gitlab_context_warns_on_bad_yaml(self, tmp_path):
        d = tmp_path / "ci"
        d.mkdir()
        (d / ".gitlab-ci.yml").write_text("build:\n  script: [make]\n")
        (d / ".gitlab-ci.yaml").write_text("bad:\n  yaml: [missing\n")
        from pipeline_check.core.checks.gitlab.base import GitLabContext
        ctx = GitLabContext.from_path(d)
        assert ctx.files_scanned == 1
        assert ctx.files_skipped == 1
        assert any("YAML parse error" in w for w in ctx.warnings)

    def test_bitbucket_context_warns_on_bad_yaml(self, tmp_path):
        d = tmp_path / "bb"
        d.mkdir()
        (d / "bitbucket-pipelines.yml").write_text("bad:\n  yaml: [missing\n")
        from pipeline_check.core.checks.bitbucket.base import BitbucketContext
        ctx = BitbucketContext.from_path(d)
        assert ctx.files_scanned == 0
        assert ctx.files_skipped == 1

    def test_azure_context_warns_on_bad_yaml(self, tmp_path):
        d = tmp_path / "ado"
        d.mkdir()
        (d / "azure-pipelines.yml").write_text("bad:\n  yaml: [missing\n")
        from pipeline_check.core.checks.azure.base import AzureContext
        ctx = AzureContext.from_path(d)
        assert ctx.files_scanned == 0
        assert ctx.files_skipped == 1

    def test_jenkins_context_tracks_read_errors(self, tmp_path):
        (tmp_path / "Jenkinsfile").write_text("pipeline { }")
        from pipeline_check.core.checks.jenkins.base import JenkinsContext
        ctx = JenkinsContext.from_path(tmp_path)
        assert ctx.files_scanned == 1
        assert ctx.files_skipped == 0


# ────────────────────────────────────────────────────────────────────────────
# WU2: Gate PASS explains conditions
# ────────────────────────────────────────────────────────────────────────────


class TestGateConditionsEvaluated:
    def test_default_gate_has_severity_condition(self):
        from pipeline_check.core.gate import GateConfig, evaluate_gate
        gate = evaluate_gate(
            [_finding(passed=True)],
            {"grade": "A"},
            GateConfig(),
        )
        assert gate.passed is True
        assert any("severity" in c for c in gate.conditions_evaluated)
        assert any("default gate" in c for c in gate.conditions_evaluated)

    def test_explicit_fail_on_recorded(self):
        from pipeline_check.core.gate import GateConfig, evaluate_gate
        gate = evaluate_gate(
            [_finding(passed=True)],
            {"grade": "A"},
            GateConfig(fail_on=Severity.HIGH),
        )
        assert any("--fail-on" in c for c in gate.conditions_evaluated)

    def test_min_grade_recorded(self):
        from pipeline_check.core.gate import GateConfig, evaluate_gate
        gate = evaluate_gate(
            [_finding(passed=True)],
            {"grade": "A"},
            GateConfig(fail_on=Severity.CRITICAL, min_grade="B"),
        )
        assert any("--min-grade" in c for c in gate.conditions_evaluated)

    def test_max_failures_recorded(self):
        from pipeline_check.core.gate import GateConfig, evaluate_gate
        gate = evaluate_gate(
            [_finding(passed=True)],
            {"grade": "A"},
            GateConfig(fail_on=Severity.CRITICAL, max_failures=10),
        )
        assert any("--max-failures" in c for c in gate.conditions_evaluated)

    def test_fail_on_checks_recorded(self):
        from pipeline_check.core.gate import GateConfig, evaluate_gate
        gate = evaluate_gate(
            [_finding(passed=True)],
            {"grade": "A"},
            GateConfig(fail_on=Severity.CRITICAL, fail_on_checks={"CB-001"}),
        )
        assert any("--fail-on-check" in c for c in gate.conditions_evaluated)


class TestGateSummaryOutput:
    def test_gate_pass_shows_effective_count(self, runner):
        findings = [_finding(passed=True), _finding(passed=False, severity=Severity.LOW)]
        with _mock_scanner_with_metadata(findings):
            result = runner.invoke(scan, ["--output", "terminal"])
        assert "[gate] PASS" in result.output
        assert "effective finding(s) evaluated" in result.output

    def test_gate_pass_shows_condition(self, runner):
        with _mock_scanner_with_metadata([_finding(passed=True)]):
            result = runner.invoke(scan, ["--output", "terminal"])
        assert "default gate" in result.output

    def test_gate_summary_always_emitted(self, runner):
        """Even with no failures, the gate summary is emitted."""
        with _mock_scanner_with_metadata([_finding(passed=True)]):
            result = runner.invoke(scan, ["--output", "terminal"])
        assert "[gate] PASS" in result.output


# ────────────────────────────────────────────────────────────────────────────
# WU3: Config discovery announcement
# ────────────────────────────────────────────────────────────────────────────


class TestConfigAnnouncement:
    def test_last_loaded_source_set_for_yaml(self, tmp_path, monkeypatch):
        monkeypatch.delenv("PIPELINE_CHECK_PIPELINE", raising=False)
        (tmp_path / ".pipeline-check.yml").write_text("pipeline: github\n")
        from pipeline_check.core.config import last_loaded_source, load_config
        load_config(cwd=tmp_path)
        src = last_loaded_source()
        assert src is not None
        assert ".pipeline-check.yml" in src

    def test_last_loaded_source_none_when_no_config(self, tmp_path, monkeypatch):
        monkeypatch.delenv("PIPELINE_CHECK_PIPELINE", raising=False)
        from pipeline_check.core.config import last_loaded_source, load_config
        load_config(cwd=tmp_path)
        assert last_loaded_source() is None

    def test_last_loaded_source_set_for_pyproject(self, tmp_path, monkeypatch):
        monkeypatch.delenv("PIPELINE_CHECK_PIPELINE", raising=False)
        (tmp_path / "pyproject.toml").write_text(
            '[tool.pipeline_check]\npipeline = "github"\n'
        )
        from pipeline_check.core.config import last_loaded_source, load_config
        load_config(cwd=tmp_path)
        src = last_loaded_source()
        assert src is not None
        assert "pyproject.toml" in src

    def test_config_loaded_message_in_cli(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".pipeline-check.yml").write_text("pipeline: github\n")
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        (wf / "ci.yml").write_text("name: ci\non: push\njobs: {}\n")
        result = runner.invoke(scan, ["--output", "json"])
        assert "[config] loaded" in result.output

    def test_quiet_suppresses_config_message(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".pipeline-check.yml").write_text("pipeline: github\n")
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        (wf / "ci.yml").write_text("name: ci\non: push\njobs: {}\n")
        result = runner.invoke(scan, ["--output", "json", "--quiet"])
        assert "[config]" not in (result.output or "")


# ────────────────────────────────────────────────────────────────────────────
# WU4: Autofix dry-run summary
# ────────────────────────────────────────────────────────────────────────────


class TestAutofixDryRunSummary:
    def test_fix_emits_summary(self, runner, tmp_path):
        """--fix emits a patch count + file count summary."""
        wf_dir = tmp_path / "workflows"
        wf_dir.mkdir()
        wf = wf_dir / "ci.yml"
        # GHA-004 (permissions) has a fixer — a workflow without permissions
        # triggers it. Use a minimal workflow that will produce a fixable finding.
        wf.write_text(
            "name: ci\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - uses: actions/checkout@v4\n"
        )
        result = runner.invoke(scan, [
            "--pipeline", "github", "--gha-path", str(wf_dir),
            "--output", "terminal", "--fix",
        ])
        # The summary line should appear in output (stderr mixed in)
        assert "[autofix]" in result.output
        assert "patch(es)" in result.output
        assert "file(s)" in result.output


# ────────────────────────────────────────────────────────────────────────────
# WU5: Verbose flag
# ────────────────────────────────────────────────────────────────────────────


class TestVerboseFlag:
    def test_verbose_emits_debug_lines(self, runner):
        with _mock_scanner_with_metadata([_finding()]):
            result = runner.invoke(scan, ["--output", "json", "-v"])
        assert "[debug] provider:" in result.output
        assert "[debug] findings:" in result.output

    def test_no_verbose_no_debug(self, runner):
        with _mock_scanner_with_metadata([_finding()]):
            result = runner.invoke(scan, ["--output", "json"])
        assert "[debug]" not in (result.output or "")

    def test_quiet_overrides_verbose(self, runner):
        with _mock_scanner_with_metadata([_finding()]):
            result = runner.invoke(scan, ["--output", "json", "-v", "-q"])
        assert "[debug]" not in (result.output or "")
        assert "[scan]" not in (result.output or "")

    def test_verbose_shows_gate_config(self, runner):
        with _mock_scanner_with_metadata([_finding()]):
            result = runner.invoke(scan, [
                "--output", "json", "-v", "--fail-on", "HIGH",
            ])
        assert "[debug] gate config:" in result.output
        assert "fail-on=HIGH" in result.output
