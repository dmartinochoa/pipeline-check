"""Per-rule tests for GitLab runner / credential rules:
GL-013 (long-lived AWS keys),
GL-014 (self-managed runner ephemeral tag),
GL-019 (vulnerability scanning),
GL-020 (token persistence).

These rules govern *who* runs the job (which runner picks it up,
which credentials it binds, whether scanning catches known-vuln
dependencies before deploy).
"""
from __future__ import annotations

from .conftest import run_check

# ── GL-013 long-lived AWS keys ──────────────────────────────────────


class TestGL013AwsLongLived:
    def test_fails_on_aws_configure_set(self):
        cfg = """
        stages: [deploy]
        deploy_job:
          stage: deploy
          image: amazon/aws-cli:2.15.0
          script:
            - aws configure set aws_access_key_id $AWS_KEY
            - aws s3 ls
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-013")
        assert not f.passed

    def test_fails_on_export_aws_key_literal(self):
        cfg = """
        stages: [deploy]
        deploy_job:
          stage: deploy
          image: amazon/aws-cli:2.15.0
          script:
            - export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
            - aws s3 ls
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-013")
        assert not f.passed

    def test_passes_when_no_static_aws_keys(self):
        cfg = """
        stages: [deploy]
        deploy_job:
          stage: deploy
          image: amazon/aws-cli:2.15.0
          id_tokens:
            AWS_ID_TOKEN: { aud: 'https://gitlab.example.com' }
          script:
            - aws sts assume-role-with-web-identity --role-arn arn:aws:iam::1:role/x --web-identity-token "$AWS_ID_TOKEN"
            - aws s3 ls
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-013")
        assert f.passed


# ── GL-014 self-managed runner ephemeral tag ────────────────────────


class TestGL014SelfHostedEphemeral:
    def test_fails_when_self_managed_lacks_ephemeral_tag(self):
        cfg = """
        stages: [build]
        build_job:
          stage: build
          image: alpine:3.19.1
          tags: [linux, x64]
          script: [make]
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-014")
        assert not f.passed

    def test_passes_with_ephemeral_tag(self):
        cfg = """
        stages: [build]
        build_job:
          stage: build
          image: alpine:3.19.1
          tags: [linux, ephemeral]
          script: [make]
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-014")
        assert f.passed

    def test_passes_with_saas_runner_tag(self):
        cfg = """
        stages: [build]
        build_job:
          stage: build
          image: alpine:3.19.1
          tags: [saas-linux-small-amd64]
          script: [make]
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-014")
        assert f.passed


# ── GL-019 vulnerability scanning ───────────────────────────────────


class TestGL019VulnScanning:
    def test_fails_when_artifact_built_without_scan(self):
        cfg = """
        stages: [build]
        build_job:
          stage: build
          image: docker:24-cli
          script:
            - docker build -t registry.example.com/app:v1 .
            - docker push registry.example.com/app:v1
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-019")
        assert not f.passed

    def test_passes_with_trivy_scan(self):
        cfg = """
        stages: [build]
        build_job:
          stage: build
          image: docker:24-cli
          script:
            - docker build -t registry.example.com/app:v1 .
            - trivy image --severity HIGH,CRITICAL registry.example.com/app:v1
            - docker push registry.example.com/app:v1
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-019")
        assert f.passed


# ── GL-020 token persistence ────────────────────────────────────────


class TestGL020TokenPersistence:
    def test_fails_when_ci_job_token_redirected_to_file(self):
        cfg = """
        stages: [build]
        build_job:
          stage: build
          image: alpine:3.19.1
          script:
            - echo $CI_JOB_TOKEN >> /tmp/token.txt
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-020")
        assert not f.passed

    def test_passes_when_token_used_inline_only(self):
        cfg = """
        stages: [build]
        build_job:
          stage: build
          image: alpine:3.19.1
          script:
            - 'curl --header "JOB-TOKEN: $CI_JOB_TOKEN" https://gitlab.example.com/api/v4/...'
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-020")
        assert f.passed
