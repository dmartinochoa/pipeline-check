"""Per-rule tests for Bitbucket BB-008 (literal secrets, full text scan),
BB-011 (long-lived AWS keys), BB-012 (curl-pipe), BB-017 (token persistence),
BB-023 (TLS bypass).

Complements the existing ``test_pipelines.py`` (BB-001..BB-005) by
covering rules 008, 011, 012, 017, 023 — the highest-impact runtime
hardening checks for any Bitbucket Pipelines repo.
"""
from __future__ import annotations

from .conftest import run_check

# ── BB-008 literal secrets (full text scan) ──────────────────────────


class TestBB008LiteralSecrets:
    def test_fails_on_aws_access_key_in_script(self):
        # Secret pasted into a script line, not a variable name.
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                script:
                  - export AWS_KEY=AKIAZ3MHALF2TESTHIJK
                  - aws s3 ls
        """
        f = run_check(cfg, "BB-008")
        assert not f.passed

    def test_fails_on_github_token_in_script(self):
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                script:
                  - export GH_TOKEN=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        """
        f = run_check(cfg, "BB-008")
        assert not f.passed

    def test_passes_when_secret_resolved_via_env_var(self):
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                script:
                  - aws s3 ls
        """
        f = run_check(cfg, "BB-008")
        assert f.passed


# ── BB-011 long-lived AWS keys ──────────────────────────────────────


class TestBB011AWSLongLived:
    def test_fails_when_aws_configure_set_in_script(self):
        # The rule scans script lines for ``aws configure set
        # aws_access_key_id`` with a LITERAL value — the documented
        # anti-pattern for injecting long-lived keys into a runtime
        # environment. (A ``$``-referenced secured variable is the
        # recommended shape and no longer fires; see the 2026-07 audit.)
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                deployment: production
                image: amazon/aws-cli:2.15.0
                script:
                  - aws configure set aws_access_key_id AKIAIOSFODNN7EXAMPLE
                  - aws s3 ls
        """
        f = run_check(cfg, "BB-011")
        assert not f.passed

    def test_fails_when_aws_key_literal_in_step_variables(self):
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                image: amazon/aws-cli:2.15.0
                variables:
                  AWS_KEY: AKIAZ3MHALF2TESTHIJK
                script:
                  - aws s3 ls
        """
        f = run_check(cfg, "BB-011")
        assert not f.passed

    def test_passes_when_no_aws_creds_referenced(self):
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                image: alpine:3.19.1
                script:
                  - make test
        """
        f = run_check(cfg, "BB-011")
        assert f.passed


# ── BB-012 curl-pipe ────────────────────────────────────────────────


class TestBB012CurlPipe:
    def test_fails_on_curl_piped_to_bash(self):
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                script:
                  - curl -fsSL https://example.com/install.sh | bash
        """
        f = run_check(cfg, "BB-012")
        assert not f.passed

    def test_fails_on_wget_piped_to_sh(self):
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                script:
                  - wget -O - https://example.com/install.sh | sh
        """
        f = run_check(cfg, "BB-012")
        assert not f.passed

    def test_passes_with_checksum_verified_install(self):
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                script:
                  - curl -fsSL https://example.com/install.sh -o install.sh
                  - sha256sum -c install.sh.sha256
                  - bash install.sh
        """
        f = run_check(cfg, "BB-012")
        assert f.passed


# ── BB-017 token persistence ────────────────────────────────────────


class TestBB017TokenPersistence:
    def test_fails_when_bitbucket_token_redirected_to_file(self):
        # The rule's regex catches ``BITBUCKET_TOKEN`` followed by
        # a redirect (``>``, ``>>``) or a tee pipe — both classic
        # patterns for persisting the build token to disk.
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                script:
                  - echo $BITBUCKET_TOKEN >> /tmp/token.txt
        """
        f = run_check(cfg, "BB-017")
        assert not f.passed

    def test_fails_when_oauth_token_piped_to_tee(self):
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                script:
                  - echo $REPOSITORY_OAUTH_ACCESS_TOKEN | tee creds.txt
        """
        f = run_check(cfg, "BB-017")
        assert not f.passed

    def test_passes_when_token_used_inline_only(self):
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                script:
                  - git push https://user:$BITBUCKET_TOKEN@bitbucket.org/x/y.git
        """
        f = run_check(cfg, "BB-017")
        assert f.passed

    def test_passes_when_no_token_referenced(self):
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                script:
                  - make test
        """
        f = run_check(cfg, "BB-017")
        assert f.passed


# ── BB-023 TLS bypass ───────────────────────────────────────────────


class TestBB023TLSBypass:
    def test_fails_on_curl_insecure_flag(self):
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                script:
                  - curl -k https://internal.example.com/secret
        """
        f = run_check(cfg, "BB-023")
        assert not f.passed

    def test_fails_on_npm_strict_ssl_false(self):
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                script:
                  - npm config set strict-ssl false
        """
        f = run_check(cfg, "BB-023")
        assert not f.passed

    def test_fails_on_clone_skip_ssl_verify(self):
        # Structural bypass: ``clone: { skip-ssl-verify: true }`` disables
        # cert verification on the repo clone itself (a YAML key + bool,
        # so it never reaches the script blob).
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                clone:
                  skip-ssl-verify: true
                script:
                  - make build
        """
        f = run_check(cfg, "BB-023")
        assert not f.passed
        assert "clone" in f.description.lower()

    def test_passes_when_no_tls_bypass(self):
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                clone:
                  skip-ssl-verify: false
                script:
                  - curl -fsSL https://example.com/data
        """
        f = run_check(cfg, "BB-023")
        assert f.passed
