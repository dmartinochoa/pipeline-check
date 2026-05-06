"""Per-rule tests for CC-005 (long-lived AWS keys) and CC-008 (literal secrets).

CC-005 fires when a job declares `AWS_ACCESS_KEY_ID` style env vars
that come from a context or environment rather than from OIDC. CC-008
fires on any string anywhere in the config that matches a known
credential pattern (AWS access key, GitHub token, Slack token, JWT,
etc.).
"""
from __future__ import annotations

from .conftest import run_check


# ── CC-005 long-lived AWS keys ───────────────────────────────────────


class TestCC005AWSLongLivedKeys:
    def test_fails_when_aws_keys_in_environment_block(self):
        # Long-lived AWS access keys mounted via the environment,
        # rather than OIDC-derived short-lived credentials.
        cfg = """
        version: 2.1
        jobs:
          deploy:
            docker:
              - image: cimg/aws:2024.03
            environment:
              AWS_ACCESS_KEY_ID: AKIAIOSFODNN7EXAMPLE
              AWS_SECRET_ACCESS_KEY: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
            steps: [checkout]
        """
        f = run_check(cfg, "CC-005")
        assert not f.passed

    def test_passes_when_no_aws_keys_referenced(self):
        cfg = """
        version: 2.1
        jobs:
          build:
            docker:
              - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
            steps: [checkout]
        """
        f = run_check(cfg, "CC-005")
        assert f.passed


# ── CC-008 literal secrets ──────────────────────────────────────────


class TestCC008LiteralSecrets:
    def test_fails_on_aws_access_key(self):
        cfg = """
        version: 2.1
        jobs:
          build:
            docker:
              - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
            environment:
              # Literal AWS access key value pasted into YAML.
              AWS_ACCESS_KEY_ID: AKIAIOSFODNN7EXAMPLE
            steps: [checkout]
        """
        f = run_check(cfg, "CC-008")
        assert not f.passed

    def test_fails_on_github_token(self):
        # A GitHub PAT (ghp_) committed to the config.
        cfg = """
        version: 2.1
        jobs:
          build:
            docker:
              - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
            environment:
              GH_TOKEN: ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
            steps: [checkout]
        """
        f = run_check(cfg, "CC-008")
        assert not f.passed

    def test_passes_when_secret_value_comes_from_context(self):
        # A real-world reference: env var name in the YAML, value
        # injected by CircleCI from a project context. The string
        # ``$SLACK_TOKEN`` is not a credential.
        cfg = """
        version: 2.1
        jobs:
          notify:
            docker:
              - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
            environment:
              SLACK_TOKEN: $SLACK_WEBHOOK
            steps: [checkout]
        """
        f = run_check(cfg, "CC-008")
        assert f.passed

    def test_passes_with_no_credential_shaped_strings(self):
        cfg = """
        version: 2.1
        jobs:
          build:
            docker:
              - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
            steps:
              - checkout
              - run: npm test
        """
        f = run_check(cfg, "CC-008")
        assert f.passed
