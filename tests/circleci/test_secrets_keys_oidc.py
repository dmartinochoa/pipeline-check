"""Per-rule tests for CircleCI secrets management, SSH keys, and OIDC trust:
CC-004 (secret-like env var not managed via context),
CC-019 (``add_ssh_keys`` without fingerprint restriction),
CC-031 (OIDC role assumption without branch filter / approval gate).

CC-004 catches inline secrets that bypass context security groups
and audit logs. CC-019 catches the bare ``add_ssh_keys`` step that
loads every project key. CC-031 narrows CC-030's ungated-context
finding to the higher-consequence cloud-role-ARN binding.
"""
from __future__ import annotations

from .conftest import run_check

# ── CC-004 secret in inline environment ─────────────────────────────


class TestCC004ContextRestrictions:
    def test_fails_when_token_in_inline_environment(self):
        cfg = """
        version: 2.1
        jobs:
          build:
            docker:
              - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
            environment:
              GITHUB_TOKEN: ${{GITHUB_TOKEN}}
            steps:
              - run:
                  no_output_timeout: 30m
                  command: gh release view
        """
        f = run_check(cfg, "CC-004")
        assert not f.passed

    def test_fails_when_password_in_inline_environment(self):
        cfg = """
        version: 2.1
        jobs:
          build:
            docker:
              - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
            environment:
              DB_PASSWORD: $DB_PASS
            steps:
              - run:
                  no_output_timeout: 30m
                  command: psql
        """
        f = run_check(cfg, "CC-004")
        assert not f.passed

    def test_passes_when_no_secret_named_env(self):
        cfg = """
        version: 2.1
        jobs:
          build:
            docker:
              - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
            environment:
              PYTHONUNBUFFERED: "1"
            steps:
              - run:
                  no_output_timeout: 30m
                  command: pytest
        """
        f = run_check(cfg, "CC-004")
        assert f.passed


# ── CC-019 add_ssh_keys without fingerprints ────────────────────────


class TestCC019AddSSHKeys:
    def test_fails_on_bare_add_ssh_keys(self):
        cfg = """
        version: 2.1
        jobs:
          deploy:
            docker:
              - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
            steps:
              - add_ssh_keys
              - run:
                  no_output_timeout: 30m
                  command: git push origin main
        """
        f = run_check(cfg, "CC-019")
        assert not f.passed

    def test_fails_on_add_ssh_keys_without_fingerprints_param(self):
        cfg = """
        version: 2.1
        jobs:
          deploy:
            docker:
              - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
            steps:
              - add_ssh_keys: {}
              - run:
                  no_output_timeout: 30m
                  command: git push origin main
        """
        f = run_check(cfg, "CC-019")
        assert not f.passed

    def test_passes_with_fingerprints_specified(self):
        cfg = """
        version: 2.1
        jobs:
          deploy:
            docker:
              - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
            steps:
              - add_ssh_keys:
                  fingerprints:
                    - "01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10"
              - run:
                  no_output_timeout: 30m
                  command: git push origin main
        """
        f = run_check(cfg, "CC-019")
        assert f.passed

    def test_passes_when_no_add_ssh_keys_step(self):
        cfg = """
        version: 2.1
        jobs:
          build:
            docker:
              - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
            steps:
              - run:
                  no_output_timeout: 30m
                  command: make
        """
        f = run_check(cfg, "CC-019")
        assert f.passed


# ── CC-031 OIDC role assumption gating ──────────────────────────────


class TestCC031OIDCTrust:
    def test_fails_when_role_arn_passed_without_branch_filter(self):
        cfg = """
        version: 2.1
        orbs:
          aws: circleci/aws-cli@5.1.0
        jobs:
          deploy:
            docker:
              - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
            steps:
              - run:
                  no_output_timeout: 30m
                  command: aws s3 ls
        workflows:
          main:
            jobs:
              - deploy:
                  context: aws-prod
                  role-arn: arn:aws:iam::1:role/deploy
        """
        f = run_check(cfg, "CC-031")
        assert not f.passed

    def test_passes_when_role_assumption_filtered_to_main(self):
        cfg = """
        version: 2.1
        orbs:
          aws: circleci/aws-cli@5.1.0
        jobs:
          deploy:
            docker:
              - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
            steps:
              - run:
                  no_output_timeout: 30m
                  command: aws s3 ls
        workflows:
          main:
            jobs:
              - hold:
                  type: approval
              - deploy:
                  requires: [hold]
                  context: aws-prod
                  role-arn: arn:aws:iam::1:role/deploy
                  filters:
                    branches:
                      only: main
        """
        f = run_check(cfg, "CC-031")
        assert f.passed

    def test_passes_when_no_role_arn_param(self):
        cfg = """
        version: 2.1
        jobs:
          build:
            docker:
              - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
            steps:
              - run:
                  no_output_timeout: 30m
                  command: make
        workflows:
          main:
            jobs: [build]
        """
        f = run_check(cfg, "CC-031")
        assert f.passed
