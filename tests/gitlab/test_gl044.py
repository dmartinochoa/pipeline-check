"""Tests for GL-044 (automatic production deployment on an MR pipeline)."""
from __future__ import annotations

from pipeline_check.core.checks.base import Severity

from .conftest import run_check


class TestGL044DeployProdOnMR:
    def test_metadata(self):
        f = run_check("build:\n  script: [make]\n", "GL-044")
        assert f.check_id == "GL-044"
        assert f.severity == Severity.CRITICAL

    def test_fails_on_auto_prod_deploy_on_mr(self):
        cfg = """
        deploy_prod:
          stage: deploy
          environment: production
          script: [./deploy.sh]
          rules:
            - if: $CI_PIPELINE_SOURCE == "merge_request_event"
        """
        f = run_check(cfg, "GL-044")
        assert not f.passed

    def test_fails_on_environment_mapping_form(self):
        cfg = """
        deploy_prod:
          environment:
            name: prod-eu
          rules:
            - if: $CI_PIPELINE_SOURCE == "merge_request_event"
        """
        f = run_check(cfg, "GL-044")
        assert not f.passed

    def test_fails_when_inherited_mr_reachability(self):
        # No job rules:/only: -> inherits a workflow: that admits MR.
        cfg = """
        workflow:
          rules:
            - if: $CI_PIPELINE_SOURCE == "merge_request_event"
        deploy_prod:
          environment: production
          script: [./deploy.sh]
        """
        f = run_check(cfg, "GL-044")
        assert not f.passed

    def test_passes_when_manual_gated(self):
        # GitLab's accepted gate: a manual prod deploy is out of scope.
        cfg = """
        deploy_prod:
          environment: production
          when: manual
          rules:
            - if: $CI_PIPELINE_SOURCE == "merge_request_event"
        """
        f = run_check(cfg, "GL-044")
        assert f.passed

    def test_passes_when_rules_manual(self):
        cfg = """
        deploy_prod:
          environment: production
          rules:
            - if: $CI_PIPELINE_SOURCE == "merge_request_event"
              when: manual
        """
        f = run_check(cfg, "GL-044")
        assert f.passed

    def test_passes_on_review_app_environment(self):
        cfg = """
        deploy_review:
          environment:
            name: review/$CI_COMMIT_REF_SLUG
          rules:
            - if: $CI_PIPELINE_SOURCE == "merge_request_event"
        """
        f = run_check(cfg, "GL-044")
        assert f.passed

    def test_passes_when_not_mr_reachable(self):
        # Production deploy gated to the default branch (post-merge).
        cfg = """
        deploy_prod:
          environment: production
          rules:
            - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
        """
        f = run_check(cfg, "GL-044")
        assert f.passed

    def test_passes_on_environment_stop_action(self):
        # A stop action tears down, it doesn't deploy code.
        cfg = """
        stop_prod:
          environment:
            name: production
            action: stop
          rules:
            - if: $CI_PIPELINE_SOURCE == "merge_request_event"
        """
        f = run_check(cfg, "GL-044")
        assert f.passed
