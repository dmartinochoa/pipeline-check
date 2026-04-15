"""Tests for the config-file loader (pyproject.toml / YAML / env)."""
from __future__ import annotations

import os

import pytest

from pipeline_check.core.config import load_config


# ────────────────────────────────────────────────────────────────────────────
# Top-level loader + precedence
# ────────────────────────────────────────────────────────────────────────────


class TestFileDiscovery:
    def test_no_file_and_no_env_returns_empty(self, tmp_path, monkeypatch):
        _clear_env(monkeypatch)
        assert load_config(cwd=tmp_path) == {}

    def test_pyproject_section_picked_up(self, tmp_path, monkeypatch):
        _clear_env(monkeypatch)
        (tmp_path / "pyproject.toml").write_text(
            '[tool.pipeline_check]\n'
            'pipeline = "gitlab"\n'
            'severity_threshold = "HIGH"\n'
        )
        cfg = load_config(cwd=tmp_path)
        assert cfg["pipeline"] == "gitlab"
        assert cfg["severity_threshold"] == "HIGH"

    def test_yaml_overrides_pyproject(self, tmp_path, monkeypatch):
        """YAML discovery wins over pyproject when both are present."""
        _clear_env(monkeypatch)
        (tmp_path / "pyproject.toml").write_text(
            '[tool.pipeline_check]\npipeline = "aws"\n'
        )
        (tmp_path / ".pipeline-check.yml").write_text(
            "pipeline: gitlab\n"
        )
        cfg = load_config(cwd=tmp_path)
        assert cfg["pipeline"] == "gitlab"

    def test_explicit_path_beats_autodiscovery(self, tmp_path, monkeypatch):
        _clear_env(monkeypatch)
        (tmp_path / ".pipeline-check.yml").write_text("pipeline: aws\n")
        other = tmp_path / "alt.toml"
        other.write_text('[tool.pipeline_check]\npipeline = "bitbucket"\n')
        cfg = load_config(explicit_path=str(other), cwd=tmp_path)
        assert cfg["pipeline"] == "bitbucket"

    def test_explicit_path_missing_raises(self, tmp_path, monkeypatch):
        _clear_env(monkeypatch)
        with pytest.raises(FileNotFoundError):
            load_config(explicit_path=str(tmp_path / "nope.toml"), cwd=tmp_path)

    def test_malformed_pyproject_returns_empty(self, tmp_path, monkeypatch):
        _clear_env(monkeypatch)
        (tmp_path / "pyproject.toml").write_text("not [[toml")
        assert load_config(cwd=tmp_path) == {}

    def test_malformed_yaml_returns_empty(self, tmp_path, monkeypatch):
        _clear_env(monkeypatch)
        (tmp_path / ".pipeline-check.yml").write_text("pipeline: [unterminated\n")
        assert load_config(cwd=tmp_path) == {}

    def test_missing_tool_section_returns_empty(self, tmp_path, monkeypatch):
        _clear_env(monkeypatch)
        (tmp_path / "pyproject.toml").write_text("[project]\nname = \"x\"\n")
        assert load_config(cwd=tmp_path) == {}


# ────────────────────────────────────────────────────────────────────────────
# Schema coverage
# ────────────────────────────────────────────────────────────────────────────


class TestSchema:
    def test_all_top_level_keys_round_trip(self, tmp_path, monkeypatch):
        _clear_env(monkeypatch)
        (tmp_path / ".pipeline-check.yml").write_text(
            "pipeline: aws\n"
            "target: my-pipe\n"
            "region: eu-west-1\n"
            "profile: work\n"
            "tf_plan: plan.json\n"
            "gha_path: .github/workflows\n"
            "gitlab_path: .gitlab-ci.yml\n"
            "bitbucket_path: bitbucket-pipelines.yml\n"
            "output: sarif\n"
            "output_file: out.sarif\n"
            "severity_threshold: MEDIUM\n"
            "checks: [CB-001, CB-002]\n"
            "standards: [owasp_cicd_top_10, nist_ssdf]\n"
        )
        cfg = load_config(cwd=tmp_path)
        assert cfg["pipeline"] == "aws"
        assert cfg["target"] == "my-pipe"
        assert cfg["region"] == "eu-west-1"
        assert cfg["profile"] == "work"
        assert cfg["tf_plan"] == "plan.json"
        assert cfg["output"] == "sarif"
        assert cfg["checks"] == ("CB-001", "CB-002")
        assert cfg["standards"] == ("owasp_cicd_top_10", "nist_ssdf")

    def test_gate_subsection_flattens_to_cli_names(self, tmp_path, monkeypatch):
        _clear_env(monkeypatch)
        (tmp_path / ".pipeline-check.yml").write_text(
            "gate:\n"
            "  fail_on: HIGH\n"
            "  min_grade: B\n"
            "  max_failures: 10\n"
            "  fail_on_checks: [GHA-002, CB-001]\n"
            "  baseline: baseline.json\n"
            "  ignore_file: .pipelinecheckignore\n"
        )
        cfg = load_config(cwd=tmp_path)
        assert cfg["fail_on"] == "HIGH"
        assert cfg["min_grade"] == "B"
        assert cfg["max_failures"] == 10
        assert cfg["fail_on_checks"] == ("GHA-002", "CB-001")
        assert cfg["baseline"] == "baseline.json"
        assert cfg["ignore_file"] == ".pipelinecheckignore"

    def test_unknown_keys_are_dropped(self, tmp_path, monkeypatch, capsys):
        _clear_env(monkeypatch)
        (tmp_path / ".pipeline-check.yml").write_text(
            "pipeline: aws\n"
            "nonsense_key: 1\n"
            "gate:\n"
            "  bogus: true\n"
        )
        cfg = load_config(cwd=tmp_path)
        assert cfg == {"pipeline": "aws"}
        err = capsys.readouterr().err
        assert "nonsense_key" in err
        assert "gate.bogus" in err

    def test_pyproject_toml_list_and_ints(self, tmp_path, monkeypatch):
        _clear_env(monkeypatch)
        (tmp_path / "pyproject.toml").write_text(
            '[tool.pipeline_check]\n'
            'checks = ["CB-001", "CB-002"]\n'
            '[tool.pipeline_check.gate]\n'
            'max_failures = 5\n'
            'fail_on_checks = ["GHA-001"]\n'
        )
        cfg = load_config(cwd=tmp_path)
        assert cfg["checks"] == ("CB-001", "CB-002")
        assert cfg["max_failures"] == 5
        assert cfg["fail_on_checks"] == ("GHA-001",)


# ────────────────────────────────────────────────────────────────────────────
# Environment variables
# ────────────────────────────────────────────────────────────────────────────


class TestEnvVars:
    def test_toplevel_env_var(self, tmp_path, monkeypatch):
        _clear_env(monkeypatch)
        monkeypatch.setenv("PIPELINE_CHECK_PIPELINE", "gitlab")
        monkeypatch.setenv("PIPELINE_CHECK_SEVERITY_THRESHOLD", "HIGH")
        cfg = load_config(cwd=tmp_path)
        assert cfg["pipeline"] == "gitlab"
        assert cfg["severity_threshold"] == "HIGH"

    def test_gate_env_var(self, tmp_path, monkeypatch):
        _clear_env(monkeypatch)
        monkeypatch.setenv("PIPELINE_CHECK_GATE_FAIL_ON", "CRITICAL")
        monkeypatch.setenv("PIPELINE_CHECK_GATE_MAX_FAILURES", "7")
        cfg = load_config(cwd=tmp_path)
        assert cfg["fail_on"] == "CRITICAL"
        assert cfg["max_failures"] == 7

    def test_comma_separated_list_env(self, tmp_path, monkeypatch):
        _clear_env(monkeypatch)
        monkeypatch.setenv("PIPELINE_CHECK_STANDARDS", "owasp_cicd_top_10,nist_ssdf")
        monkeypatch.setenv("PIPELINE_CHECK_GATE_FAIL_ON_CHECKS", "GHA-001,GHA-002")
        cfg = load_config(cwd=tmp_path)
        assert cfg["standards"] == ("owasp_cicd_top_10", "nist_ssdf")
        assert cfg["fail_on_checks"] == ("GHA-001", "GHA-002")

    def test_env_overrides_file(self, tmp_path, monkeypatch):
        _clear_env(monkeypatch)
        (tmp_path / ".pipeline-check.yml").write_text("pipeline: aws\n")
        monkeypatch.setenv("PIPELINE_CHECK_PIPELINE", "bitbucket")
        cfg = load_config(cwd=tmp_path)
        assert cfg["pipeline"] == "bitbucket"

    def test_unknown_env_var_ignored(self, tmp_path, monkeypatch):
        _clear_env(monkeypatch)
        monkeypatch.setenv("PIPELINE_CHECK_NONSENSE", "x")
        monkeypatch.setenv("PIPELINE_CHECK_GATE_BOGUS", "x")
        cfg = load_config(cwd=tmp_path)
        assert cfg == {}


# ────────────────────────────────────────────────────────────────────────────
# End-to-end CLI integration (CLI beats env beats file)
# ────────────────────────────────────────────────────────────────────────────


class TestCliIntegration:
    def test_config_file_supplies_default(self, tmp_path, monkeypatch):
        import json
        from click.testing import CliRunner
        from pipeline_check.cli import scan

        _clear_env(monkeypatch)
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".pipeline-check.yml").write_text(
            "pipeline: gitlab\n"
        )
        (tmp_path / ".gitlab-ci.yml").write_text("build: {script: [make]}\n")
        result = CliRunner().invoke(scan, ["--output", "json"])
        assert result.exit_code in (0, 1), result.output
        payload = json.loads(result.stdout)
        # Config-supplied `pipeline: gitlab` actually took effect — only
        # GitLab check IDs should be emitted.
        emitted = {f["check_id"] for f in payload["findings"]}
        assert emitted == {"GL-001", "GL-002", "GL-003", "GL-004", "GL-005", "GL-006", "GL-007", "GL-008", "GL-009"}

    def test_cli_flag_overrides_config(self, tmp_path, monkeypatch):
        import json
        from click.testing import CliRunner
        from pipeline_check.cli import scan

        _clear_env(monkeypatch)
        monkeypatch.chdir(tmp_path)
        # Config file says gitlab, but CLI flag chooses terraform.
        (tmp_path / ".pipeline-check.yml").write_text("pipeline: gitlab\n")
        (tmp_path / "plan.json").write_text(
            '{"planned_values": {"root_module": {"resources": []}}}'
        )
        # Also create a .gitlab-ci.yml so IF gitlab was picked we'd see GL-*.
        (tmp_path / ".gitlab-ci.yml").write_text("build: {script: [make]}\n")
        result = CliRunner().invoke(scan, [
            "--pipeline", "terraform",
            "--tf-plan", "plan.json",
            "--output", "json",
        ])
        assert result.exit_code in (0, 1), result.output
        payload = json.loads(result.stdout)
        # CLI flag won: NO GitLab findings should appear. An empty terraform
        # plan has no resources, so findings is empty — and critically, no
        # GL-* IDs leaked in.
        emitted = {f["check_id"] for f in payload["findings"]}
        assert not any(cid.startswith("GL-") for cid in emitted)

    def test_env_overrides_config(self, tmp_path, monkeypatch):
        import json
        from click.testing import CliRunner
        from pipeline_check.cli import scan

        _clear_env(monkeypatch)
        monkeypatch.chdir(tmp_path)
        # Config says aws, env says gitlab — env should win.
        (tmp_path / ".pipeline-check.yml").write_text("pipeline: aws\n")
        monkeypatch.setenv("PIPELINE_CHECK_PIPELINE", "gitlab")
        (tmp_path / ".gitlab-ci.yml").write_text("build: {script: [make]}\n")
        result = CliRunner().invoke(scan, ["--output", "json"])
        assert result.exit_code in (0, 1), result.output
        payload = json.loads(result.stdout)
        # GitLab provider actually ran — AWS would need real creds and
        # emit CB-*/IAM-*/etc. ids, none of which should appear here.
        emitted = {f["check_id"] for f in payload["findings"]}
        assert emitted == {"GL-001", "GL-002", "GL-003", "GL-004", "GL-005", "GL-006", "GL-007", "GL-008", "GL-009"}

    def test_gate_config_file_tightens_gate(self, tmp_path, monkeypatch):
        from click.testing import CliRunner
        from pipeline_check.cli import scan

        _clear_env(monkeypatch)
        monkeypatch.chdir(tmp_path)
        # GHA-001 fires as HIGH on an unpinned action; default gate only
        # fails on CRITICAL. Config file ratchets it down to HIGH.
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        (wf / "c.yml").write_text(
            "on: push\n"
            "jobs:\n"
            "  b:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
        )
        (tmp_path / ".pipeline-check.yml").write_text(
            "pipeline: github\n"
            "gate:\n"
            "  fail_on: HIGH\n"
        )
        result = CliRunner().invoke(scan, ["--output", "json"])
        assert result.exit_code == 1

    def test_explicit_config_flag_missing_file_errors(self, tmp_path, monkeypatch):
        from click.testing import CliRunner
        from pipeline_check.cli import scan

        _clear_env(monkeypatch)
        monkeypatch.chdir(tmp_path)
        result = CliRunner().invoke(scan, [
            "--config", str(tmp_path / "does-not-exist.toml"),
            "--output", "json",
        ])
        assert result.exit_code != 0
        assert "not found" in result.output.lower() or "does-not-exist" in result.output


# ────────────────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────────────────


def _clear_env(monkeypatch):
    """Remove any PIPELINE_CHECK_* env vars that may leak from the host."""
    for name in list(os.environ):
        if name.startswith("PIPELINE_CHECK_"):
            monkeypatch.delenv(name, raising=False)
