"""Tests for ADO-033 (IaC apply on a PR-validated pipeline)."""
from __future__ import annotations

from .conftest import run_check


class TestADO033IacApplyOnPr:
    def test_fails_on_terraform_apply_with_pr_validation(self) -> None:
        f = run_check("""
        trigger: [main]
        pr: [main]
        steps:
          - script: |
              terraform init
              terraform apply -auto-approve
        """, "ADO-033")
        assert not f.passed
        assert "apply" in f.description.lower()

    def test_fails_inside_stage_and_job(self) -> None:
        f = run_check("""
        pr:
          branches:
            include: [main]
        stages:
          - stage: infra
            jobs:
              - job: tf
                steps:
                  - bash: terragrunt apply
        """, "ADO-033")
        assert not f.passed

    def test_passes_when_only_plan_on_pr(self) -> None:
        f = run_check("""
        trigger: [main]
        pr: [main]
        steps:
          - script: terraform plan
        """, "ADO-033")
        assert f.passed

    def test_passes_when_pipeline_not_pr_validated(self) -> None:
        # No ``pr:`` key: the apply runs only on the default-branch leg,
        # not on untrusted PR content, so the rule is out of scope.
        f = run_check("""
        trigger: [main]
        steps:
          - script: terraform apply -auto-approve
        """, "ADO-033")
        assert f.passed

    def test_passes_when_pr_explicitly_none(self) -> None:
        f = run_check("""
        trigger: [main]
        pr: none
        steps:
          - script: terraform apply -auto-approve
        """, "ADO-033")
        assert f.passed

    def test_fails_on_pulumi_up_variant(self) -> None:
        # The shared IAC_APPLY_RE primitive covers the whole family.
        f = run_check("""
        pr: [main]
        steps:
          - script: pulumi up --yes
        """, "ADO-033")
        assert not f.passed
