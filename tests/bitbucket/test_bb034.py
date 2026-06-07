"""Tests for BB-034 (production deployment on a pull-request pipeline)."""
from __future__ import annotations

from pipeline_check.core.checks.base import Severity

from .conftest import run_check


class TestBB034DeployProdOnPR:
    def test_metadata(self):
        f = run_check(
            "pipelines:\n  default:\n    - step:\n        script: [echo hi]\n",
            "BB-034",
        )
        assert f.check_id == "BB-034"
        assert f.severity == Severity.CRITICAL

    def test_fails_on_production_deploy_in_pull_requests(self):
        cfg = """
        pipelines:
          pull-requests:
            '**':
              - step:
                  name: deploy
                  deployment: production
                  script: [./deploy.sh]
        """
        f = run_check(cfg, "BB-034")
        assert not f.passed

    def test_fails_on_prod_tier_name_variant(self):
        # ``prod-eu`` is a production-tier name; case-insensitive.
        cfg = """
        pipelines:
          pull-requests:
            '**':
              - step:
                  deployment: Prod-EU
                  script: [./deploy.sh]
        """
        f = run_check(cfg, "BB-034")
        assert not f.passed

    def test_fails_inside_parallel_pr_step(self):
        cfg = """
        pipelines:
          pull-requests:
            '**':
              - parallel:
                  - step:
                      script: [echo build]
                  - step:
                      deployment: production
                      script: [./deploy.sh]
        """
        f = run_check(cfg, "BB-034")
        assert not f.passed

    def test_passes_on_preview_environment_in_pull_requests(self):
        # Per-PR preview deploys are the intended pattern, not flagged.
        cfg = """
        pipelines:
          pull-requests:
            '**':
              - step:
                  deployment: preview
                  script: [./deploy-preview.sh]
        """
        f = run_check(cfg, "BB-034")
        assert f.passed

    def test_passes_on_staging_in_pull_requests(self):
        # Staging is out of scope; only production tier fires.
        cfg = """
        pipelines:
          pull-requests:
            '**':
              - step:
                  deployment: staging
                  script: [./deploy.sh]
        """
        f = run_check(cfg, "BB-034")
        assert f.passed

    def test_passes_on_production_deploy_in_branches_section(self):
        # Production deploy on the default branch (post-merge) is correct.
        cfg = """
        pipelines:
          branches:
            main:
              - step:
                  deployment: production
                  script: [./deploy.sh]
        """
        f = run_check(cfg, "BB-034")
        assert f.passed

    def test_does_not_misfire_on_product_named_environment(self):
        # ``product-tests`` is not a production tier.
        cfg = """
        pipelines:
          pull-requests:
            '**':
              - step:
                  deployment: product-tests
                  script: [./test.sh]
        """
        f = run_check(cfg, "BB-034")
        assert f.passed
