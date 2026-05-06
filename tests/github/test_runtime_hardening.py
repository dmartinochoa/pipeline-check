"""Per-rule tests for GitHub Actions runtime-hardening rules:
GHA-008 (literal secrets), GHA-012 (self-hosted ephemeral marker),
GHA-014 (deploy job environment), GHA-015 (timeout-minutes),
GHA-016 (curl-pipe), GHA-019 (token persistence), GHA-023 (TLS bypass).

Complements the existing ``test_workflows.py`` (GHA-001..GHA-005) by
covering the runtime-hardening half of the GitHub catalog. Each rule
gets a positive case (compliant), at least one negative case (triggers
finding), and an edge case where applicable.
"""
from __future__ import annotations

from .conftest import run_check

# ── GHA-008 literal secrets ─────────────────────────────────────────


class TestGHA008LiteralSecrets:
    def test_fails_on_aws_access_key_in_env(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            env:
              AWS_ACCESS_KEY_ID: AKIAIOSFODNN7EXAMPLE
            steps: [{run: 'aws s3 ls'}]
        """
        f = run_check(wf, "GHA-008")
        assert not f.passed

    def test_fails_on_github_token_literal(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            env:
              GH_TOKEN: ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
            steps: [{run: 'gh release view'}]
        """
        f = run_check(wf, "GHA-008")
        assert not f.passed

    def test_passes_when_secrets_referenced_via_secrets_context(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            env:
              AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
            steps: [{run: 'aws s3 ls'}]
        """
        f = run_check(wf, "GHA-008")
        assert f.passed


# ── GHA-015 timeout-minutes ─────────────────────────────────────────


class TestGHA015TimeoutMinutes:
    def test_fails_when_job_has_no_timeout(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps: [{run: './long-build.sh'}]
        """
        f = run_check(wf, "GHA-015")
        assert not f.passed

    def test_passes_with_explicit_timeout(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps: [{run: './long-build.sh'}]
        """
        f = run_check(wf, "GHA-015")
        assert f.passed


# ── GHA-016 curl-pipe ───────────────────────────────────────────────


class TestGHA016CurlPipe:
    def test_fails_on_curl_piped_to_bash(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: curl -fsSL https://example.com/install.sh | bash
        """
        f = run_check(wf, "GHA-016")
        assert not f.passed

    def test_fails_on_wget_piped_to_sh(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: wget -O - https://example.com/install.sh | sh
        """
        f = run_check(wf, "GHA-016")
        assert not f.passed

    def test_passes_with_checksum_verified_install(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: |
                  curl -fsSL https://example.com/install.sh -o install.sh
                  sha256sum -c install.sh.sha256
                  bash install.sh
        """
        f = run_check(wf, "GHA-016")
        assert f.passed


# ── GHA-019 token persistence ───────────────────────────────────────


class TestGHA019TokenPersistence:
    def test_fails_when_token_redirected_to_file(self):
        # The rule fires on patterns where GITHUB_TOKEN is appended
        # to a file via ``>>``, piped through ``tee``, or written
        # into ``$GITHUB_ENV`` / ``$GITHUB_OUTPUT`` / ``$GITHUB_STATE``.
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: echo $GITHUB_TOKEN >> /tmp/token.txt
        """
        f = run_check(wf, "GHA-019")
        assert not f.passed

    def test_fails_when_token_piped_to_tee(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: echo $GITHUB_TOKEN | tee creds.txt
        """
        f = run_check(wf, "GHA-019")
        assert not f.passed

    def test_fails_when_secret_written_to_github_output(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: echo "TOKEN=$GITHUB_TOKEN" >> $GITHUB_OUTPUT
        """
        f = run_check(wf, "GHA-019")
        assert not f.passed

    def test_passes_when_token_used_inline_only(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: gh release view --token $GITHUB_TOKEN
        """
        f = run_check(wf, "GHA-019")
        assert f.passed


# ── GHA-023 TLS bypass ──────────────────────────────────────────────


class TestGHA023TLSBypass:
    def test_fails_on_curl_insecure_flag(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: curl -k https://internal.example.com/secret
        """
        f = run_check(wf, "GHA-023")
        assert not f.passed

    def test_fails_on_npm_strict_ssl_false(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: npm config set strict-ssl false
        """
        f = run_check(wf, "GHA-023")
        assert not f.passed

    def test_passes_when_no_tls_bypass(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: curl -fsSL https://example.com/data
        """
        f = run_check(wf, "GHA-023")
        assert f.passed


# ── GHA-012 self-hosted runner ──────────────────────────────────────


class TestGHA012SelfHostedEphemeral:
    def test_fails_when_self_hosted_lacks_ephemeral(self):
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: [self-hosted, linux, x64]
            timeout-minutes: 30
            steps:
              - run: make
        """
        f = run_check(wf, "GHA-012")
        assert not f.passed

    def test_passes_with_ephemeral_label(self):
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: [self-hosted, linux, ephemeral]
            timeout-minutes: 30
            steps:
              - run: make
        """
        f = run_check(wf, "GHA-012")
        assert f.passed

    def test_passes_on_github_hosted_runner(self):
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: make
        """
        f = run_check(wf, "GHA-012")
        assert f.passed


# ── GHA-014 deploy job environment ──────────────────────────────────


class TestGHA014DeployEnvironment:
    def test_fails_when_deploy_job_has_no_environment(self):
        wf = """
        name: release
        on: push
        permissions: { contents: read }
        jobs:
          deploy:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: deploy.sh production
        """
        f = run_check(wf, "GHA-014")
        assert not f.passed

    def test_passes_with_explicit_environment(self):
        wf = """
        name: release
        on: push
        permissions: { contents: read }
        jobs:
          deploy:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            environment: production
            steps:
              - run: deploy.sh production
        """
        f = run_check(wf, "GHA-014")
        assert f.passed

    def test_passes_for_non_deploy_job(self):
        # Lint-only job, no deploy keyword in name. Rule shouldn't fire.
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          lint:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: ruff check .
        """
        f = run_check(wf, "GHA-014")
        assert f.passed
