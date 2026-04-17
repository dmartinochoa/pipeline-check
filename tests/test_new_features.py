"""Tests locking in the v2 feature set (SARIF enrichment, autofix
expansion, diff-mode parity, baseline-from-git, --standard-report,
--config-check, glob check selection, Lambda fan-out, --fix --apply,
and HTML filter markup)."""
from __future__ import annotations

import json
from unittest.mock import MagicMock

from click.testing import CliRunner

from pipeline_check.cli import scan
from pipeline_check.core import autofix
from pipeline_check.core import diff as diff_mod
from pipeline_check.core.checks.base import Finding, Severity


def _f(check_id, resource="x", severity=Severity.MEDIUM, passed=False) -> Finding:
    return Finding(
        check_id=check_id, title="t", severity=severity,
        resource=resource, description="d", recommendation="r", passed=passed,
    )


# ── SARIF enrichment ─────────────────────────────────────────────────────

def test_sarif_emits_start_line_for_gha001(tmp_path):
    from pipeline_check.core.sarif_reporter import report_sarif
    wf = tmp_path / "ci.yml"
    wf.write_text("jobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n")
    sarif = json.loads(report_sarif([_f("GHA-001", str(wf), Severity.HIGH)], {"grade": "A", "score": 90, "summary": {}}))
    loc = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert loc["region"]["startLine"] == 4


def test_sarif_includes_arn_property_for_aws_resources():
    from pipeline_check.core.sarif_reporter import report_sarif
    arn = "arn:aws:codebuild:eu-west-1:111:project/app"
    sarif = json.loads(report_sarif([_f("CB-001", arn, Severity.HIGH)], {"grade": "A", "score": 90, "summary": {}}))
    props = sarif["runs"][0]["results"][0]["properties"]
    assert props["arn"] == arn
    assert props["region"] == "eu-west-1"


# ── Glob check selection ─────────────────────────────────────────────────

def test_glob_check_selection(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".gitlab-ci.yml").write_text("build: {script: [make]}\n")
    result = CliRunner().invoke(scan, [
        "--pipeline", "gitlab", "--checks", "GL-00[12]",
        "--output", "json",
    ])
    payload = json.loads(result.stdout)
    ids = {f["check_id"] for f in payload["findings"]}
    assert ids <= {"GL-001", "GL-002"}
    assert ids, "glob should have matched at least one check"


# ── --config-check ───────────────────────────────────────────────────────

def test_config_check_exits_nonzero_on_unknown_key(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".pipeline-check.yml").write_text("pipeline: aws\nbogus_key: 1\n")
    result = CliRunner().invoke(scan, ["--config-check"])
    assert result.exit_code == 3
    assert "bogus_key" in result.output


def test_config_check_ok_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".pipeline-check.yml").write_text("pipeline: github\n")
    result = CliRunner().invoke(scan, ["--config-check"])
    assert result.exit_code == 0
    assert "OK" in result.output


# ── --standard-report ────────────────────────────────────────────────────

def test_standard_report_prints_matrix():
    result = CliRunner().invoke(scan, ["--standard-report", "owasp_cicd_top_10"])
    assert result.exit_code == 0
    # Matrix headers + at least one control line.
    assert "Control -> check mapping" in result.output
    assert "CICD-SEC-" in result.output


def test_standard_report_unknown_name():
    result = CliRunner().invoke(scan, ["--standard-report", "no_such_std"])
    assert result.exit_code != 0
    assert "Unknown standard" in result.output


# ── Diff-mode parity ─────────────────────────────────────────────────────

def test_diff_base_rejected_for_aws(monkeypatch):
    """AWS + --diff-base should raise rather than silently ignore."""
    from pipeline_check.core import providers as providers_mod
    fake_provider = MagicMock()
    fake_provider.check_classes = []
    fake_provider.build_context.return_value = MagicMock()
    monkeypatch.setattr(providers_mod, "get", lambda name: fake_provider if name == "aws" else None)

    import pytest

    from pipeline_check.core.scanner import Scanner
    with pytest.raises(ValueError, match="not supported for the AWS provider"):
        Scanner(pipeline="aws", diff_base="origin/main")


# ── --baseline-from-git ──────────────────────────────────────────────────

def test_baseline_from_git_resolves_via_git_show(monkeypatch):
    from pipeline_check.core.gate import load_baseline_from_git
    prior = json.dumps({"findings": [
        {"check_id": "GHA-001", "resource": "wf.yml", "passed": False},
    ]})
    monkeypatch.setattr(diff_mod, "git_show", lambda ref, path, cwd=".": prior)
    pairs = load_baseline_from_git("origin/main", "baseline.json")
    assert pairs == {("GHA-001", "wf.yml")}


def test_baseline_from_git_empty_on_git_failure(monkeypatch):
    from pipeline_check.core.gate import load_baseline_from_git
    monkeypatch.setattr(diff_mod, "git_show", lambda *a, **kw: None)
    assert load_baseline_from_git("origin/main", "baseline.json") == set()


# ── --fix --apply ────────────────────────────────────────────────────────

def test_fix_apply_modifies_file_in_place(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    target = wf / "ci.yml"
    target.write_text(
        "name: ci\non: push\njobs:\n  b:\n    runs-on: ubuntu\n"
        "    steps:\n      - run: echo\n"
    )
    result = CliRunner().invoke(
        scan, ["--pipeline", "github", "--fix", "--apply", "--output", "terminal"]
    )
    assert "1 file(s) modified" in result.output
    assert "permissions:" in target.read_text()


def test_apply_without_fix_raises():
    result = CliRunner().invoke(scan, ["--pipeline", "aws", "--apply"])
    assert result.exit_code != 0
    assert "--apply requires --fix" in result.output


# ── Autofix expansion ────────────────────────────────────────────────────

def test_gha002_fixer_adds_persist_credentials():
    wf = (
        "jobs:\n"
        "  build:\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
    )
    out = autofix.generate_fix(_f("GHA-002", "x", Severity.CRITICAL), wf)
    assert out is not None
    assert "persist-credentials: false" in out


def test_gha002_fixer_idempotent_when_already_set():
    wf = (
        "jobs:\n"
        "  build:\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n"
        "          persist-credentials: false\n"
    )
    assert autofix.generate_fix(_f("GHA-002", "x", Severity.CRITICAL), wf) is None


def test_gha008_fixer_redacts_literal_secret():
    wf = 'env:\n  AWS_KEY: AKIAIOSFODNN7EXAMPLE\n'
    out = autofix.generate_fix(_f("GHA-008", "x", Severity.CRITICAL), wf)
    assert out is not None
    assert "AKIA" not in out
    assert "<REDACTED>" in out
    assert "TODO" in out


# ── Lambda fan-out ───────────────────────────────────────────────────────

def test_lambda_fanout_aggregates_scans(monkeypatch):
    from pipeline_check import lambda_handler as lh
    calls: list[dict] = []

    def fake_handler(event, ctx):
        # First call is the fan-out entry; route it through the real
        # handler to exercise the branch. Subsequent calls are the
        # per-region legacy scans — short-circuit them.
        if "regions" in event or "providers" in event:
            return lh._fan_out(
                regions=event.get("regions", []),
                providers=event.get("providers", []),
            )
        calls.append(event)
        return {
            "statusCode": 200, "grade": "B", "score": 80,
            "total_findings": 3, "critical_failures": 1,
            "report_s3_key": None, "report_s3_status": "unconfigured",
        }
    monkeypatch.setattr(lh, "handler", fake_handler)

    result = lh._fan_out(regions=["us-east-1", "eu-west-1"], providers=["aws"])
    assert result["statusCode"] == 200
    assert len(result["scans"]) == 2
    assert result["worst_grade"] == "B"
    assert result["total_critical_failures"] == 2
    # Per-scan payload annotated with region + provider.
    assert {s["region"] for s in result["scans"]} == {"us-east-1", "eu-west-1"}


# ── HTML filter markup ───────────────────────────────────────────────────

def test_html_report_includes_filter_bar_and_copy_ignore():
    from pipeline_check.core.html_reporter import report_html
    findings = [_f("GHA-001", "wf.yml", Severity.HIGH)]
    html = report_html(findings, {"grade": "A", "score": 95, "summary": {}})
    assert 'id="f-sev"' in html
    assert 'id="f-std"' in html
    assert 'id="f-prov"' in html
    assert 'copy-ignore-btn' in html
    assert 'data-rule="GHA-001:wf.yml"' in html
    # Row is annotated for JS filtering.
    assert 'data-severity="HIGH"' in html
    assert 'data-provider="github"' in html
