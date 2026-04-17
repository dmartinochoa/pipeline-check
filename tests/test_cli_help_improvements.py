"""Regression tests for the --help / user-error / --list-checks pass.

Scope: exclusively the new behaviours added in the code-review round.
Broader CLI behaviour is covered by test_cli.py and test_manual.py.
"""
from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from pipeline_check.cli import scan


# ─── Bug fixes ─────────────────────────────────────────────────────────────


def test_cfn_cb004_accepts_stringified_timeout(tmp_path):
    """CFN TimeoutInMinutes: "30" (string form from parameter defaults)
    used to false-positive as "timeout unset". Regression check."""
    from pipeline_check.core.checks.cloudformation.base import CloudFormationContext
    from pipeline_check.core.checks.cloudformation.codebuild import CodeBuildChecks

    template = {
        "Resources": {
            "P": {
                "Type": "AWS::CodeBuild::Project",
                "Properties": {
                    "Name": "p",
                    "Environment": {"Image": "aws/codebuild/standard:7.0"},
                    "TimeoutInMinutes": "30",   # string form
                    "Source": {"Type": "NO_SOURCE"},
                },
            },
        },
    }
    ctx = CloudFormationContext.__new__(CloudFormationContext)
    ctx._templates = [("<test>", template)]
    from pipeline_check.core.checks.cloudformation.base import _iter_resources
    ctx._resources = list(_iter_resources(ctx._templates))
    f = next(x for x in CodeBuildChecks(ctx).run() if x.check_id == "CB-004")
    assert f.passed is True


def test_cfn_cb004_accepts_int_timeout_still_works(tmp_path):
    """Integer form remains a passing case."""
    from pipeline_check.core.checks.cloudformation.base import CloudFormationContext
    from pipeline_check.core.checks.cloudformation.codebuild import CodeBuildChecks

    template = {
        "Resources": {
            "P": {
                "Type": "AWS::CodeBuild::Project",
                "Properties": {
                    "Name": "p",
                    "Environment": {"Image": "aws/codebuild/standard:7.0"},
                    "TimeoutInMinutes": 30,
                    "Source": {"Type": "NO_SOURCE"},
                },
            },
        },
    }
    ctx = CloudFormationContext.__new__(CloudFormationContext)
    ctx._templates = [("<test>", template)]
    from pipeline_check.core.checks.cloudformation.base import _iter_resources
    ctx._resources = list(_iter_resources(ctx._templates))
    assert next(x for x in CodeBuildChecks(ctx).run() if x.check_id == "CB-004").passed is True


def test_cfn_cb004_rejects_non_numeric_timeout():
    """Non-numeric strings still fail — ``"default"`` / intrinsics count as
    "no explicit bound set"."""
    from pipeline_check.core.checks.cloudformation.base import CloudFormationContext
    from pipeline_check.core.checks.cloudformation.codebuild import CodeBuildChecks

    template = {
        "Resources": {
            "P": {
                "Type": "AWS::CodeBuild::Project",
                "Properties": {
                    "Name": "p",
                    "Environment": {"Image": "aws/codebuild/standard:7.0"},
                    "TimeoutInMinutes": {"Ref": "BuildTimeout"},  # intrinsic
                    "Source": {"Type": "NO_SOURCE"},
                },
            },
        },
    }
    ctx = CloudFormationContext.__new__(CloudFormationContext)
    ctx._templates = [("<test>", template)]
    from pipeline_check.core.checks.cloudformation.base import _iter_resources
    ctx._resources = list(_iter_resources(ctx._templates))
    assert next(x for x in CodeBuildChecks(ctx).run() if x.check_id == "CB-004").passed is False


# ─── User-error control ────────────────────────────────────────────────────


def test_cli_rejects_baseline_missing_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "template.yml").write_text(
        "Resources:\n  B:\n    Type: AWS::S3::Bucket\n    Properties: {}\n"
    )
    result = CliRunner().invoke(
        scan,
        ["--pipeline", "cloudformation", "--baseline", "does-not-exist.json"],
    )
    assert result.exit_code != 0
    assert "baseline file not found" in result.output.lower()


def test_cli_rejects_fix_with_inventory_only(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "template.yml").write_text(
        "Resources:\n  B:\n    Type: AWS::S3::Bucket\n    Properties: {}\n"
    )
    result = CliRunner().invoke(
        scan,
        ["--pipeline", "cloudformation", "--inventory-only", "--fix"],
    )
    assert result.exit_code != 0
    assert "--fix cannot be combined with --inventory-only" in result.output


def test_cli_rejects_diffbase_with_inventory_only(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "template.yml").write_text(
        "Resources:\n  B:\n    Type: AWS::S3::Bucket\n    Properties: {}\n"
    )
    result = CliRunner().invoke(
        scan,
        ["--pipeline", "cloudformation", "--inventory-only",
         "--diff-base", "origin/main"],
    )
    assert result.exit_code != 0
    assert "--diff-base cannot be combined with --inventory-only" in result.output


def test_cli_rejects_baseline_with_inventory_only(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "template.yml").write_text(
        "Resources:\n  B:\n    Type: AWS::S3::Bucket\n    Properties: {}\n"
    )
    (tmp_path / "prior.json").write_text("{}")
    result = CliRunner().invoke(
        scan,
        ["--pipeline", "cloudformation", "--inventory-only",
         "--baseline", str(tmp_path / "prior.json")],
    )
    assert result.exit_code != 0
    assert "--baseline cannot be combined with --inventory-only" in result.output


def test_cli_cfn_empty_directory_diagnoses_the_problem(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    empty = tmp_path / "empty-dir"
    empty.mkdir()
    result = CliRunner().invoke(
        scan,
        ["--pipeline", "cloudformation", "--cfn-template", str(empty)],
    )
    assert result.exit_code != 0
    assert "contains no" in result.output
    assert ".yml" in result.output


# ─── Help / --man / --list-checks ──────────────────────────────────────────


def test_man_inventory_topic_exists():
    result = CliRunner().invoke(scan, ["--man", "inventory"])
    assert result.exit_code == 0
    assert "TOPIC: inventory" in result.output
    # Key content the user should see.
    assert "--inventory-only" in result.output
    assert "--inventory-type" in result.output


def test_man_index_lists_inventory_topic():
    result = CliRunner().invoke(scan, ["--man"])
    assert result.exit_code == 0
    assert "inventory" in result.output
    assert "Available topics:" in result.output


def test_list_checks_rule_based_provider():
    result = CliRunner().invoke(scan, ["--pipeline", "github", "--list-checks"])
    assert result.exit_code == 0
    # Format: ID  SEV  TITLE
    assert "GHA-001" in result.output
    # At least one CRITICAL / HIGH / MEDIUM appears.
    assert any(sev in result.output for sev in ("CRITICAL", "HIGH", "MEDIUM"))


def test_list_checks_class_based_provider():
    result = CliRunner().invoke(scan, ["--pipeline", "aws", "--list-checks"])
    assert result.exit_code == 0
    # AWS has both class-based (CB-001..007) and rule-based (CB-008..).
    assert "CB-001" in result.output
    assert "CB-008" in result.output
    # Sort check — CB-001 before CB-002.
    lines = result.output.strip().splitlines()
    cb_lines = [line for line in lines if line.startswith("CB-")]
    ids = [line.split()[0] for line in cb_lines]
    assert ids == sorted(ids)


def test_list_checks_cloudformation_provider():
    result = CliRunner().invoke(scan, ["--pipeline", "cloudformation", "--list-checks"])
    assert result.exit_code == 0
    # CFN core: CB-001..007 via class-based docstring.
    assert "CB-001" in result.output


def test_pipeline_help_lists_available_values():
    """The --help output for --pipeline must enumerate the choices so
    new users don't have to guess."""
    result = CliRunner().invoke(scan, ["--help"])
    assert result.exit_code == 0
    # All 9 provider names appear somewhere in --help text.
    for provider in ("aws", "terraform", "cloudformation", "github",
                     "gitlab", "bitbucket", "azure", "jenkins", "circleci"):
        assert provider in result.output


def test_inventory_only_help_mentions_mutual_exclusion():
    result = CliRunner().invoke(scan, ["--help"])
    assert result.exit_code == 0
    # Look for at least one of the mutex hints near --inventory-only.
    assert "Mutually exclusive" in result.output or "cannot be combined" in result.output or "--fix" in result.output
