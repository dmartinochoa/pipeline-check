"""Per-rule tests for CircleCI workflow-level gating and execution
controls:
CC-009 (deploy job requires manual approval gate),
CC-010 (self-hosted runner ephemeral marker),
CC-011 (``store_test_results`` step archives test output),
CC-013 (deploy job restricted to a branch via ``filters``).

These rules govern *when* and *where* a job runs (which workflow
edge precedes it, which runner picks it up, which branch is
allowed). Together with the test-result archival they form the
control-plane half of CircleCI hygiene.
"""
from __future__ import annotations

from .conftest import run_check

# ── CC-009 deploy approval gate ─────────────────────────────────────


class TestCC009DeployApproval:
    def test_fails_when_deploy_job_lacks_approval(self):
        cfg = """
        version: 2.1
        jobs:
          deploy:
            docker:
              - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
            steps:
              - run:
                  no_output_timeout: 30m
                  command: deploy.sh production
        workflows:
          main:
            jobs:
              - deploy
        """
        f = run_check(cfg, "CC-009")
        assert not f.passed

    def test_passes_when_deploy_requires_approval_job(self):
        cfg = """
        version: 2.1
        jobs:
          deploy:
            docker:
              - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
            steps:
              - run:
                  no_output_timeout: 30m
                  command: deploy.sh production
        workflows:
          main:
            jobs:
              - hold-prod:
                  type: approval
              - deploy:
                  requires: [hold-prod]
        """
        f = run_check(cfg, "CC-009")
        assert f.passed

    def test_fails_on_underscore_deploy_job_name(self):
        # ``deploy_prod`` is the dominant CI naming form; a ``\b`` regex
        # missed it because ``_`` is a word char (B4 FN, shared
        # deploy-name primitive).
        cfg = """
        version: 2.1
        jobs:
          deploy_prod:
            docker:
              - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
            steps:
              - run:
                  no_output_timeout: 30m
                  command: ./ship.sh
        workflows:
          main:
            jobs:
              - deploy_prod
        """
        f = run_check(cfg, "CC-009")
        assert not f.passed


# ── CC-010 self-hosted runner ephemeral marker ──────────────────────


class TestCC010SelfHostedRunner:
    def test_fails_when_self_hosted_lacks_ephemeral(self):
        cfg = """
        version: 2.1
        jobs:
          build:
            machine: true
            resource_class: my-org/self-hosted-large
            steps:
              - run:
                  no_output_timeout: 30m
                  command: make
        """
        f = run_check(cfg, "CC-010")
        assert not f.passed

    def test_passes_when_self_hosted_is_ephemeral(self):
        cfg = """
        version: 2.1
        jobs:
          build:
            machine: true
            resource_class: my-org/self-hosted-ephemeral
            steps:
              - run:
                  no_output_timeout: 30m
                  command: make
        """
        f = run_check(cfg, "CC-010")
        assert f.passed

    def test_passes_with_shared_resource_class(self):
        cfg = """
        version: 2.1
        jobs:
          build:
            docker:
              - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
            resource_class: medium
            steps:
              - run:
                  no_output_timeout: 30m
                  command: make
        """
        f = run_check(cfg, "CC-010")
        assert f.passed


# ── CC-011 store_test_results ───────────────────────────────────────


class TestCC011StoreTestResults:
    def test_fails_when_no_store_test_results_step(self):
        cfg = """
        version: 2.1
        jobs:
          test:
            docker:
              - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
            steps:
              - run:
                  no_output_timeout: 30m
                  command: pytest
        """
        f = run_check(cfg, "CC-011")
        assert not f.passed

    def test_passes_when_store_test_results_present(self):
        cfg = """
        version: 2.1
        jobs:
          test:
            docker:
              - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
            steps:
              - run:
                  no_output_timeout: 30m
                  command: pytest --junitxml=test-results/junit.xml
              - store_test_results:
                  path: test-results
        """
        f = run_check(cfg, "CC-011")
        assert f.passed


# ── CC-013 branch filter ────────────────────────────────────────────


class TestCC013BranchFilter:
    def test_fails_when_deploy_lacks_branch_filter(self):
        cfg = """
        version: 2.1
        jobs:
          deploy:
            docker:
              - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
            steps:
              - run:
                  no_output_timeout: 30m
                  command: deploy.sh
        workflows:
          main:
            jobs:
              - hold:
                  type: approval
              - deploy:
                  requires: [hold]
        """
        f = run_check(cfg, "CC-013")
        assert not f.passed

    def test_passes_when_deploy_filtered_to_main(self):
        cfg = """
        version: 2.1
        jobs:
          deploy:
            docker:
              - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
            steps:
              - run:
                  no_output_timeout: 30m
                  command: deploy.sh
        workflows:
          main:
            jobs:
              - hold:
                  type: approval
              - deploy:
                  requires: [hold]
                  filters:
                    branches:
                      only: main
        """
        f = run_check(cfg, "CC-013")
        assert f.passed

    def test_fails_on_underscore_deploy_job_name(self):
        cfg = """
        version: 2.1
        jobs:
          release_prod:
            docker:
              - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
            steps:
              - run:
                  no_output_timeout: 30m
                  command: ./ship.sh
        workflows:
          main:
            jobs:
              - release_prod
        """
        f = run_check(cfg, "CC-013")
        assert not f.passed
