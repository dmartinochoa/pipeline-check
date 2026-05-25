"""Unit tests for the direct-HCL Terraform parser."""
from __future__ import annotations

import textwrap

import pytest

hcl2 = pytest.importorskip("hcl2", reason="python-hcl2 not installed")

from pipeline_check.core.checks.terraform._hcl_parser import (
    HclParseResult,
    parse_tf_directory,
)
from pipeline_check.core.checks.terraform.base import TerraformContext


def _write_tf(tmp_path, filename, content):
    p = tmp_path / filename
    p.write_text(textwrap.dedent(content), encoding="utf-8")
    return p


# ── Variable resolution ─────────────────────────────────────────────────


class TestVariableResolution:
    def test_variable_with_default_resolves(self, tmp_path):
        _write_tf(tmp_path, "main.tf", """\
            variable "region" {
              default = "us-east-1"
            }
            resource "aws_s3_bucket" "b" {
              bucket = "my-${var.region}-bucket"
            }
        """)
        result = parse_tf_directory(tmp_path)
        assert len(result.resources) == 1
        assert result.resources[0].values["bucket"] == "my-us-east-1-bucket"

    def test_variable_without_default_stays_opaque(self, tmp_path):
        _write_tf(tmp_path, "main.tf", """\
            variable "env" {
              type = string
            }
            resource "aws_s3_bucket" "b" {
              bucket = "${var.env}-bucket"
            }
        """)
        result = parse_tf_directory(tmp_path)
        assert "${var.env}" in result.resources[0].values["bucket"]
        assert "var.env" in result.unresolved_refs

    def test_full_interpolation_preserves_type(self, tmp_path):
        _write_tf(tmp_path, "main.tf", """\
            variable "enable" {
              default = true
            }
            resource "aws_codebuild_project" "app" {
              name = "app"
              environment {
                privileged_mode = var.enable
              }
            }
        """)
        result = parse_tf_directory(tmp_path)
        r = result.resources[0]
        env = r.values["environment"][0]
        assert env["privileged_mode"] is True

    def test_local_referencing_variable_resolves(self, tmp_path):
        _write_tf(tmp_path, "main.tf", """\
            variable "project" {
              default = "myapp"
            }
            locals {
              full_name = "${var.project}-service"
            }
            resource "aws_s3_bucket" "b" {
              bucket = "${local.full_name}-bucket"
            }
        """)
        result = parse_tf_directory(tmp_path)
        assert result.resources[0].values["bucket"] == "myapp-service-bucket"

    def test_circular_locals_stay_unresolved(self, tmp_path):
        _write_tf(tmp_path, "main.tf", """\
            locals {
              a = "${local.b}-x"
              b = "${local.a}-y"
            }
            resource "aws_s3_bucket" "b" {
              bucket = "${local.a}"
            }
        """)
        result = parse_tf_directory(tmp_path)
        assert "${local.a}" in result.resources[0].values["bucket"]


# ── Resource synthesis ──────────────────────────────────────────────────


class TestResourceSynthesis:
    def test_single_resource(self, tmp_path):
        _write_tf(tmp_path, "main.tf", """\
            resource "aws_s3_bucket" "data" {
              bucket = "my-bucket"
            }
        """)
        result = parse_tf_directory(tmp_path)
        assert len(result.resources) == 1
        r = result.resources[0]
        assert r.type == "aws_s3_bucket"
        assert r.name == "data"
        assert r.address == "aws_s3_bucket.data"
        assert r.values["bucket"] == "my-bucket"

    def test_multiple_resources_same_type(self, tmp_path):
        _write_tf(tmp_path, "main.tf", """\
            resource "aws_s3_bucket" "a" {
              bucket = "bucket-a"
            }
            resource "aws_s3_bucket" "b" {
              bucket = "bucket-b"
            }
        """)
        result = parse_tf_directory(tmp_path)
        assert len(result.resources) == 2
        names = {r.name for r in result.resources}
        assert names == {"a", "b"}

    def test_data_source_extraction(self, tmp_path):
        _write_tf(tmp_path, "main.tf", """\
            data "aws_iam_policy_document" "trust" {
              statement {
                actions = ["sts:AssumeRole"]
              }
            }
        """)
        result = parse_tf_directory(tmp_path)
        assert len(result.data_sources) == 1
        d = result.data_sources[0]
        assert d.type == "aws_iam_policy_document"
        assert d.address == "data.aws_iam_policy_document.trust"

    def test_nested_blocks_are_lists(self, tmp_path):
        _write_tf(tmp_path, "main.tf", """\
            resource "aws_codebuild_project" "app" {
              name = "app"
              environment {
                compute_type = "BUILD_GENERAL1_SMALL"
                image = "aws/codebuild/standard:7.0"
              }
            }
        """)
        result = parse_tf_directory(tmp_path)
        env = result.resources[0].values["environment"]
        assert isinstance(env, list)
        assert isinstance(env[0], dict)
        assert env[0]["compute_type"] == "BUILD_GENERAL1_SMALL"


# ── File discovery ──────────────────────────────────────────────────────


class TestFileDiscovery:
    def test_only_tf_files_parsed(self, tmp_path):
        _write_tf(tmp_path, "main.tf", 'resource "aws_s3_bucket" "b" { bucket = "x" }')
        (tmp_path / "notes.txt").write_text("not terraform")
        (tmp_path / "backup.tf.bak").write_text("not terraform")
        result = parse_tf_directory(tmp_path)
        assert len(result.resources) == 1

    def test_empty_directory(self, tmp_path):
        result = parse_tf_directory(tmp_path)
        assert result.resources == []
        assert result.data_sources == []

    def test_unparseable_file_adds_warning(self, tmp_path):
        (tmp_path / "bad.tf").write_text("this is not valid { hcl {{{{")
        _write_tf(tmp_path, "good.tf", 'resource "aws_s3_bucket" "b" { bucket = "x" }')
        result = parse_tf_directory(tmp_path)
        assert len(result.resources) == 1
        assert any("parse error" in w for w in result.warnings)

    def test_multiple_files_merged(self, tmp_path):
        _write_tf(tmp_path, "buckets.tf", 'resource "aws_s3_bucket" "a" { bucket = "a" }')
        _write_tf(tmp_path, "roles.tf", 'resource "aws_iam_role" "r" { name = "r" }')
        result = parse_tf_directory(tmp_path)
        assert len(result.resources) == 2
        types = {r.type for r in result.resources}
        assert types == {"aws_s3_bucket", "aws_iam_role"}


# ── Child module walking ────────────────────────────────────────────────


class TestChildModules:
    def test_local_module_walked(self, tmp_path):
        _write_tf(tmp_path, "main.tf", """\
            module "child" {
              source = "./child"
            }
        """)
        child = tmp_path / "child"
        child.mkdir()
        _write_tf(child, "main.tf", """\
            resource "aws_s3_bucket" "inner" {
              bucket = "inner-bucket"
            }
        """)
        result = parse_tf_directory(tmp_path)
        assert any(
            r.address == "module.child.aws_s3_bucket.inner"
            for r in result.resources
        )

    def test_remote_module_skipped(self, tmp_path):
        _write_tf(tmp_path, "main.tf", """\
            module "vpc" {
              source  = "terraform-aws-modules/vpc/aws"
              version = "5.0.0"
            }
        """)
        result = parse_tf_directory(tmp_path)
        assert result.resources == []


# ── TerraformContext integration ────────────────────────────────────────


class TestContextIntegration:
    def test_from_hcl_dir_produces_valid_context(self, tmp_path):
        _write_tf(tmp_path, "main.tf", """\
            resource "aws_s3_bucket" "b" {
              bucket = "my-bucket"
            }
        """)
        ctx = TerraformContext.from_hcl_dir(tmp_path)
        assert ctx.source_mode == "hcl"
        assert len(list(ctx.resources())) == 1
        assert len(list(ctx.resources("aws_s3_bucket"))) == 1
        assert len(list(ctx.resources("aws_iam_role"))) == 0

    def test_unresolved_refs_generate_warning(self, tmp_path):
        _write_tf(tmp_path, "main.tf", """\
            variable "env" {
              type = string
            }
            resource "aws_s3_bucket" "b" {
              bucket = "${var.env}-bucket"
            }
        """)
        ctx = TerraformContext.from_hcl_dir(tmp_path)
        assert ctx.unresolved_refs
        assert any("[hcl]" in w for w in ctx.warnings)

    def test_resources_with_unresolved_tracked(self, tmp_path):
        _write_tf(tmp_path, "main.tf", """\
            variable "name" {}
            resource "aws_s3_bucket" "b" {
              bucket = "${var.name}"
            }
        """)
        ctx = TerraformContext.from_hcl_dir(tmp_path)
        assert "aws_s3_bucket.b" in ctx._resources_with_unresolved


# ── Rule firing integration ─────────────────────────────────────────────


class TestRuleFiring:
    def test_cb002_privileged_mode_fires(self, tmp_path):
        _write_tf(tmp_path, "main.tf", """\
            resource "aws_codebuild_project" "app" {
              name = "app"
              environment {
                compute_type = "BUILD_GENERAL1_SMALL"
                image = "aws/codebuild/standard:7.0"
                privileged_mode = true
              }
              source {
                type = "CODEPIPELINE"
              }
            }
        """)
        from pipeline_check.core.checks.terraform.workflows import TerraformRuleChecks

        ctx = TerraformContext.from_hcl_dir(tmp_path)
        findings = TerraformRuleChecks(ctx).run()
        failed_ids = {f.check_id for f in findings if not f.passed}
        assert "CB-002" in failed_ids

    def test_cb001_plaintext_secret_fires(self, tmp_path):
        _write_tf(tmp_path, "main.tf", """\
            resource "aws_codebuild_project" "app" {
              name = "app"
              environment {
                compute_type = "BUILD_GENERAL1_SMALL"
                image = "aws/codebuild/standard:7.0"
                environment_variable {
                  name  = "SECRET_KEY"
                  value = "hunter2"
                }
              }
              source {
                type = "CODEPIPELINE"
              }
            }
        """)
        from pipeline_check.core.checks.terraform.workflows import TerraformRuleChecks

        ctx = TerraformContext.from_hcl_dir(tmp_path)
        findings = TerraformRuleChecks(ctx).run()
        failed_ids = {f.check_id for f in findings if not f.passed}
        assert "CB-001" in failed_ids

    def test_ecr002_mutable_tags_fires(self, tmp_path):
        _write_tf(tmp_path, "main.tf", """\
            resource "aws_ecr_repository" "app" {
              name                 = "app"
              image_tag_mutability = "MUTABLE"
            }
        """)
        from pipeline_check.core.checks.terraform.workflows import TerraformRuleChecks

        ctx = TerraformContext.from_hcl_dir(tmp_path)
        findings = TerraformRuleChecks(ctx).run()
        failed_ids = {f.check_id for f in findings if not f.passed}
        assert "ECR-002" in failed_ids


# ── Confidence demotion ─────────────────────────────────────────────────


class TestConfidenceDemotion:
    def test_findings_demoted_for_unresolved_resources(self, tmp_path):
        _write_tf(tmp_path, "main.tf", """\
            variable "env" {}
            resource "aws_codebuild_project" "app" {
              name = "${var.env}-app"
              environment {
                compute_type = "BUILD_GENERAL1_SMALL"
                image = "aws/codebuild/standard:7.0"
                privileged_mode = true
              }
              source {
                type = "CODEPIPELINE"
              }
            }
        """)
        from pipeline_check.core.checks.base import Confidence
        from pipeline_check.core.checks.terraform.workflows import TerraformRuleChecks

        ctx = TerraformContext.from_hcl_dir(tmp_path)
        assert "aws_codebuild_project.app" in ctx._resources_with_unresolved
        findings = TerraformRuleChecks(ctx).run()
        cb002 = [f for f in findings if f.check_id == "CB-002" and not f.passed]
        assert cb002
        assert cb002[0].confidence != Confidence.HIGH

    def test_findings_not_demoted_for_resolved_resources(self, tmp_path):
        _write_tf(tmp_path, "main.tf", """\
            resource "aws_codebuild_project" "app" {
              name = "app"
              environment {
                compute_type = "BUILD_GENERAL1_SMALL"
                image = "aws/codebuild/standard:7.0"
                privileged_mode = true
              }
              source {
                type = "CODEPIPELINE"
              }
            }
        """)
        from pipeline_check.core.checks.base import Confidence
        from pipeline_check.core.checks.terraform.workflows import TerraformRuleChecks

        ctx = TerraformContext.from_hcl_dir(tmp_path)
        assert "aws_codebuild_project.app" not in ctx._resources_with_unresolved
        findings = TerraformRuleChecks(ctx).run()
        cb002 = [f for f in findings if f.check_id == "CB-002" and not f.passed]
        assert cb002
        assert cb002[0].confidence == Confidence.HIGH
