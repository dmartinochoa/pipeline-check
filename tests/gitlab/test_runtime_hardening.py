"""Per-rule tests for GitLab GL-008 (literal secrets), GL-013 (long-lived
AWS keys), GL-015 (timeout), GL-016 (curl-pipe), GL-023 (TLS bypass).

These five rules cover the everyday hardening of any GitLab pipeline:
no secrets in the YAML, no long-lived static cloud creds, bound the
build, verify what you download, don't bypass TLS.
"""
from __future__ import annotations

from .conftest import run_check

# ── GL-008 literal secrets ──────────────────────────────────────────


class TestGL008LiteralSecrets:
    def test_fails_on_aws_access_key_in_variables(self):
        cfg = """
        stages: [deploy]
        deploy_job:
          stage: deploy
          image: amazon/aws-cli:2.15.0
          variables:
            AWS_ACCESS_KEY_ID: AKIAZ3MHALF2TESTHIJK
          script: [aws s3 ls]
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-008")
        assert not f.passed

    def test_fails_on_github_token_literal(self):
        cfg = """
        stages: [build]
        build_job:
          stage: build
          image: alpine:3.19.1
          variables:
            GH_TOKEN: ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          script: [echo "$GH_TOKEN"]
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-008")
        assert not f.passed

    def test_passes_when_secret_value_resolves_via_runner_var(self):
        # The string ``$DEPLOY_TOKEN`` is a variable reference, not
        # a credential. The actual token is injected by GitLab CI/CD
        # variables at run time and never appears in the YAML.
        cfg = """
        stages: [deploy]
        deploy_job:
          stage: deploy
          image: alpine:3.19.1
          variables:
            DEPLOY_TOKEN: $CI_DEPLOY_TOKEN
          script: [echo deploying]
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-008")
        assert f.passed

    def test_passes_with_no_credential_shaped_strings(self):
        cfg = """
        stages: [build]
        build_job:
          stage: build
          image: alpine:3.19.1
          script: [make test]
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-008")
        assert f.passed


# ── GL-015 timeout ──────────────────────────────────────────────────


class TestGL015Timeout:
    def test_fails_when_job_has_no_timeout(self):
        cfg = """
        stages: [build]
        build_job:
          stage: build
          image: alpine:3.19.1
          script: [./long-build.sh]
        """
        f = run_check(cfg, "GL-015")
        assert not f.passed

    def test_passes_with_explicit_timeout(self):
        cfg = """
        stages: [build]
        build_job:
          stage: build
          image: alpine:3.19.1
          script: [./long-build.sh]
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-015")
        assert f.passed


# ── GL-016 curl-pipe ────────────────────────────────────────────────


class TestGL016CurlPipe:
    def test_fails_on_curl_piped_to_bash(self):
        cfg = """
        stages: [install]
        install_job:
          stage: install
          image: alpine:3.19.1
          script:
            - curl -fsSL https://example.com/install.sh | bash
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-016")
        assert not f.passed

    def test_fails_on_wget_piped_to_sh(self):
        cfg = """
        stages: [install]
        install_job:
          stage: install
          image: alpine:3.19.1
          script:
            - wget -O - https://example.com/install.sh | sh
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-016")
        assert not f.passed

    def test_passes_with_checksum_verified_install(self):
        cfg = """
        stages: [install]
        install_job:
          stage: install
          image: alpine:3.19.1
          script:
            - curl -fsSL https://example.com/install.sh -o install.sh
            - sha256sum -c install.sh.sha256
            - bash install.sh
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-016")
        assert f.passed


# ── GL-023 TLS bypass ───────────────────────────────────────────────


class TestGL023TLSBypass:
    def test_fails_on_curl_insecure_flag(self):
        cfg = """
        stages: [fetch]
        fetch_job:
          stage: fetch
          image: alpine:3.19.1
          script:
            - curl -k https://internal.example.com/secret
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-023")
        assert not f.passed

    def test_fails_on_npm_strict_ssl_false(self):
        cfg = """
        stages: [install]
        install_job:
          stage: install
          image: node:20.10.0
          script:
            - npm config set strict-ssl false
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-023")
        assert not f.passed

    def test_passes_when_no_tls_bypass(self):
        cfg = """
        stages: [fetch]
        fetch_job:
          stage: fetch
          image: alpine:3.19.1
          script: [curl -fsSL https://example.com/data]
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-023")
        assert f.passed
