"""Tests for GL-041 (IaC apply on an untrusted merge-request trigger)."""
from __future__ import annotations

from .conftest import run_check


class TestGL041IacApplyUntrustedMr:
    def test_fails_on_terraform_apply_with_mr_rule(self) -> None:
        f = run_check("""
        terraform_apply:
          stage: deploy
          script:
            - terraform init
            - terraform apply -auto-approve
          rules:
            - if: $CI_PIPELINE_SOURCE == "merge_request_event"
        """, "GL-041")
        assert not f.passed
        assert "terraform_apply" in f.description
        assert f.job_anchors == ("terraform_apply",)

    def test_fails_on_legacy_only_merge_requests(self) -> None:
        f = run_check("""
        deploy:
          only:
            - merge_requests
          script:
            - cdk deploy --require-approval never
        """, "GL-041")
        assert not f.passed

    def test_fails_when_workflow_admits_mr_and_job_has_no_rules(self) -> None:
        f = run_check("""
        workflow:
          rules:
            - if: $CI_PIPELINE_SOURCE == "merge_request_event"
        apply:
          script:
            - pulumi up --yes
        """, "GL-041")
        assert not f.passed

    def test_fails_on_terragrunt_destroy(self) -> None:
        f = run_check("""
        nuke:
          script:
            - terragrunt destroy -auto-approve
          rules:
            - if: $CI_PIPELINE_SOURCE == "merge_request_event"
        """, "GL-041")
        assert not f.passed

    def test_fails_on_tofu_apply(self) -> None:
        # OpenTofu (the Terraform fork) shares the apply sink.
        f = run_check("""
        deploy:
          script:
            - tofu apply -auto-approve
          rules:
            - if: $CI_PIPELINE_SOURCE == "merge_request_event"
        """, "GL-041")
        assert not f.passed

    def test_fails_on_terragrunt_run_all_apply(self) -> None:
        # ``terragrunt run-all apply`` realizes state across every module.
        f = run_check("""
        deploy:
          script:
            - terragrunt run-all apply -auto-approve
          rules:
            - if: $CI_PIPELINE_SOURCE == "merge_request_event"
        """, "GL-041")
        assert not f.passed

    def test_passes_on_plan_only_on_mr(self) -> None:
        f = run_check("""
        terraform_plan:
          script:
            - terraform plan
          rules:
            - if: $CI_PIPELINE_SOURCE == "merge_request_event"
        """, "GL-041")
        assert f.passed

    def test_passes_when_apply_gated_to_default_branch(self) -> None:
        f = run_check("""
        terraform_apply:
          environment: production
          script:
            - terraform apply -auto-approve
          rules:
            - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
              when: manual
        """, "GL-041")
        assert f.passed

    def test_passes_when_apply_only_on_push_to_main(self) -> None:
        # A job whose own rules restrict it to a branch push is not
        # reachable from a merge-request pipeline, so no finding.
        f = run_check("""
        deploy:
          script:
            - terraform apply -auto-approve
          rules:
            - if: $CI_COMMIT_BRANCH == "main"
        """, "GL-041")
        assert f.passed

    def test_passes_when_no_apply_command(self) -> None:
        f = run_check("""
        build:
          script:
            - make build
          rules:
            - if: $CI_PIPELINE_SOURCE == "merge_request_event"
        """, "GL-041")
        assert f.passed

    def test_passes_on_empty_pipeline(self) -> None:
        f = run_check("""
        build:
          script: [make]
        """, "GL-041")
        assert f.passed
