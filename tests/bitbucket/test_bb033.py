"""Tests for BB-033 (IaC apply on a pull-request pipeline)."""
from __future__ import annotations

from pipeline_check.core.checks.base import Severity

from .conftest import run_check


class TestBB033IacApplyOnPR:
    def test_metadata(self):
        f = run_check("pipelines:\n  default:\n    - step:\n        script: [echo hi]\n", "BB-033")
        assert f.check_id == "BB-033"
        assert f.severity == Severity.CRITICAL

    def test_fails_on_apply_in_pull_requests(self):
        cfg = """
        pipelines:
          pull-requests:
            '**':
              - step:
                  name: tf
                  script:
                    - terraform init
                    - terraform apply -auto-approve
        """
        f = run_check(cfg, "BB-033")
        assert not f.passed

    def test_fails_on_apply_in_after_script(self):
        cfg = """
        pipelines:
          pull-requests:
            '**':
              - step:
                  script: [echo build]
                  after-script:
                    - pulumi up --yes
        """
        f = run_check(cfg, "BB-033")
        assert not f.passed

    def test_passes_on_plan_only_in_pull_requests(self):
        cfg = """
        pipelines:
          pull-requests:
            '**':
              - step:
                  script: [terraform plan]
        """
        f = run_check(cfg, "BB-033")
        assert f.passed

    def test_passes_on_apply_in_branches_section(self):
        # apply on the default branch (post-merge) is the correct place.
        cfg = """
        pipelines:
          branches:
            main:
              - step:
                  deployment: production
                  script: [terraform apply -auto-approve]
        """
        f = run_check(cfg, "BB-033")
        assert f.passed
