"""CLI ease-of-use tests — auto-detect, grouped help, init, short flags, hints."""
from __future__ import annotations

from unittest.mock import patch

import pytest
from click.testing import CliRunner

from pipeline_check.cli import (
    _detect_all_pipelines_from_cwd,
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

    def test_detects_kubernetes(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "kubernetes").mkdir()
        assert _detect_pipeline_from_cwd() == "kubernetes"

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

    def test_scan_auto_refuses_when_no_ci_files_present(
        self, runner, tmp_path, monkeypatch,
    ):
        # Behavior change: prior to UX-3, auto-mode in a directory
        # with no CI files silently fell through to ``--pipeline aws``,
        # which produced 14 INFO-severity "API access failed" findings
        # on machines without AWS credentials and a misleading
        # "Grade A / Score 100" headline. New behavior: refuse with a
        # concrete hint that includes ``--pipeline aws`` for users who
        # actually wanted the AWS scan.
        monkeypatch.chdir(tmp_path)
        with patch("pipeline_check.cli.Scanner") as MS:
            MS.return_value.run.return_value = []
            MS.return_value.metadata = _mock_meta()
            result = runner.invoke(scan, [])
        # click.UsageError exits with code 2.
        assert result.exit_code != 0
        combined = (result.output or "") + (result.stderr or "")
        assert "no CI/CD config files detected" in combined
        assert "--pipeline aws" in combined  # opt-in hint
        # Scanner must NOT have been instantiated — no phantom scan.
        MS.assert_not_called()

    def test_scan_explicit_aws_still_works_in_empty_cwd(
        self, runner, tmp_path, monkeypatch,
    ):
        # The opt-in path for AWS users: passing --pipeline aws keeps
        # working in directories without CI files, since it's an
        # explicit request, not an auto-fallback guess.
        monkeypatch.chdir(tmp_path)
        with patch("pipeline_check.cli.Scanner") as MS:
            MS.return_value.run.return_value = []
            MS.return_value.metadata = _mock_meta()
            result = runner.invoke(scan, ["--pipeline", "aws"])
        assert result.exit_code == 0
        assert MS.call_args.kwargs["pipeline"] == "aws"

    def test_degraded_scan_warning_when_all_findings_are_dash_000(
        self, runner, tmp_path, monkeypatch,
    ):
        # When every emitted finding is a ``<PREFIX>-000`` API-access-
        # failed degraded marker, the score still reads 100/Grade A
        # (degraded findings are INFO and don't count toward the
        # weighted score), which is mathematically right but visually
        # confusing. The CLI must surface a ``[warn]`` line so the
        # operator knows the score reflects only modules that
        # returned data.
        monkeypatch.chdir(tmp_path)
        degraded_findings = [
            Finding(
                check_id=f"{prefix}-000",
                title=f"{prefix} API access failed",
                severity=Severity.INFO,
                resource=prefix,
                description="Could not enumerate.",
                recommendation="Configure credentials.",
                passed=False,
            )
            for prefix in ("CB", "CP", "IAM", "S3")
        ]
        with patch("pipeline_check.cli.Scanner") as MS:
            MS.return_value.run.return_value = degraded_findings
            MS.return_value.metadata = _mock_meta()
            MS.return_value.chains = []
            result = runner.invoke(scan, ["--pipeline", "aws"])
        assert result.exit_code == 0
        combined = (result.output or "") + (result.stderr or "")
        assert "scan degraded: 4 module(s) failed API access" in combined


class TestMultiAutoDetect:
    """``--pipeline auto`` (default) walks every provider's canonical
    files at cwd and switches to multi-provider mode when more than one
    matches, so cross-provider chains (XPC-NNN) fire automatically.
    """

    def test_all_returns_each_match(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".github" / "workflows").mkdir(parents=True)
        (tmp_path / "Dockerfile").write_text("FROM scratch\n")
        detected = _detect_all_pipelines_from_cwd()
        assert "github" in detected
        assert "dockerfile" in detected

    def test_all_returns_empty_for_empty_dir(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        assert _detect_all_pipelines_from_cwd() == []

    def test_helm_drops_kubernetes_when_both_match(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "Chart.yaml").write_text("name: x\n")
        (tmp_path / "kubernetes").mkdir()
        detected = _detect_all_pipelines_from_cwd()
        assert "helm" in detected
        assert "kubernetes" not in detected

    def test_scan_routes_two_matches_to_multiscanner(
        self, runner, tmp_path, monkeypatch,
    ):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".github" / "workflows").mkdir(parents=True)
        (tmp_path / "Dockerfile").write_text("FROM scratch\n")
        with patch("pipeline_check.cli.MultiScanner") as MS:
            MS.return_value.run.return_value = []
            MS.return_value.metadata_by_provider = {}
            MS.return_value.metadata = _mock_meta()
            MS.return_value.chains = []
            result = runner.invoke(scan, [])
        assert result.exit_code == 0
        assert "[auto] detected providers" in result.stderr
        assert "github" in result.stderr
        assert "dockerfile" in result.stderr
        assert MS.call_args.kwargs["pipelines"] == ["github", "dockerfile"]

    def test_scan_routes_single_match_to_scanner(
        self, runner, tmp_path, monkeypatch,
    ):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "Dockerfile").write_text("FROM scratch\n")
        with patch("pipeline_check.cli.Scanner") as MS:
            MS.return_value.run.return_value = []
            MS.return_value.metadata = _mock_meta()
            result = runner.invoke(scan, [])
        assert result.exit_code == 0
        assert "[auto] detected --pipeline dockerfile" in result.stderr
        assert MS.call_args.kwargs["pipeline"] == "dockerfile"


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

    def test_redirected_stdout_is_utf8_on_windows(self, tmp_path):
        # Regression: Windows redirected stdout used cp1252, which
        # mojibakes the · and … characters Rich emits. On non-Windows
        # the default is already UTF-8 so this is a no-op assertion.
        import subprocess
        import sys
        out = tmp_path / "out.txt"
        with open(out, "wb") as fh:
            subprocess.run(
                [sys.executable, "-m", "pipeline_check", "--help"],
                stdout=fh, stderr=subprocess.DEVNULL, timeout=30,
            )
        raw = out.read_bytes()
        # Decode as UTF-8 — must not raise.
        text = raw.decode("utf-8", errors="strict")
        assert "Pipeline-Check" in text

    def test_python_dash_m_entry_point_works(self):
        # ``python -m pipeline_check --help`` is the canonical fallback
        # when the console script isn't on PATH (fresh virtualenv,
        # rootless containers). It must succeed and print the same
        # help text as the installed script.
        import subprocess
        import sys
        result = subprocess.run(
            [sys.executable, "-m", "pipeline_check", "--help"],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0, (
            f"python -m pipeline_check --help failed:\n"
            f"stdout: {result.stdout!r}\nstderr: {result.stderr!r}"
        )
        assert "Pipeline-Check" in result.stdout
        assert "--pipeline" in result.stdout


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

    def test_npm_alongside_github_hint_fires_on_sibling_package_json(
        self, runner, tmp_path, monkeypatch,
    ):
        # Mimic the cicd-goat scenario 20 layout: a github workflow
        # tree plus a sibling package.json that the npm provider would
        # catch if the user also ran ``--pipelines github,npm``.
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".github" / "workflows").mkdir(parents=True)
        (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
            "name: ci\non: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps: [{run: echo}]\n",
            encoding="utf-8",
        )
        (tmp_path / "scenarios" / "20-dep").mkdir(parents=True)
        (tmp_path / "scenarios" / "20-dep" / "package.json").write_text(
            '{"name": "x", "dependencies": {"lodash": "^4"}}\n',
            encoding="utf-8",
        )
        result = runner.invoke(scan, ["--pipeline", "github"])
        assert "[hint]" in result.stderr
        assert "package.json" in result.stderr
        assert "--pipeline npm" in result.stderr or "--pipelines github,npm" in result.stderr

    def test_npm_hint_silent_when_no_package_json(
        self, runner, tmp_path, monkeypatch,
    ):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".github" / "workflows").mkdir(parents=True)
        (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
            "name: ci\non: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps: [{run: echo}]\n",
            encoding="utf-8",
        )
        result = runner.invoke(scan, ["--pipeline", "github"])
        assert "package.json" not in (result.stderr or "")

    def test_npm_hint_silent_in_multi_pipeline_github_npm(
        self, runner, tmp_path, monkeypatch,
    ):
        # User already opted into npm coverage; no nudge needed.
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".github" / "workflows").mkdir(parents=True)
        (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
            "name: ci\non: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps: [{run: echo}]\n",
            encoding="utf-8",
        )
        (tmp_path / "package.json").write_text(
            '{"name": "x", "dependencies": {}}\n',
            encoding="utf-8",
        )
        result = runner.invoke(scan, ["--pipelines", "github,npm"])
        # Hint about npm coverage being missing must NOT appear when
        # npm is already in the resolved pipeline list.
        assert "rerun with" not in (result.stderr or "")
        assert "[hint] this repo also ships package.json" not in (result.stderr or "")

    def test_npm_hint_skips_node_modules(
        self, runner, tmp_path, monkeypatch,
    ):
        # node_modules forests produce tens of thousands of nested
        # package.json files; the hint walker must not surface those.
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".github" / "workflows").mkdir(parents=True)
        (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
            "name: ci\non: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps: [{run: echo}]\n",
            encoding="utf-8",
        )
        (tmp_path / "node_modules" / "lodash").mkdir(parents=True)
        (tmp_path / "node_modules" / "lodash" / "package.json").write_text(
            '{"name": "lodash"}\n', encoding="utf-8",
        )
        result = runner.invoke(scan, ["--pipeline", "github"])
        # No first-party package.json elsewhere in the tree; hint
        # should NOT fire on node_modules/ alone.
        assert "package.json" not in (result.stderr or "")
