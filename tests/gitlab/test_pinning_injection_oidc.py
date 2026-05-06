"""Per-rule tests for GitLab digest pinning, services pinning, shell
injection, and OIDC trust:
GL-009 (image pinned by tag rather than sha256 digest),
GL-026 (dangerous shell idiom — eval / sh -c "$VAR" / backtick),
GL-028 (services: image not pinned),
GL-031 (id_tokens: block missing audience pin).

GL-001 fails floating tags at HIGH; GL-009 is the stricter
sha256 tier. GL-028 covers the same pin contract for sidecar
``services:`` images that GL-001/GL-009 cover for ``image:``.
GL-031 closes the federation-trust gap that GHA-030 covers on
GitHub: an unbound OIDC audience accepts the token from any
consumer trusting GitLab's issuer.
"""
from __future__ import annotations

from .conftest import run_check

# ── GL-009 image digest pinning ─────────────────────────────────────


class TestGL009DigestPinning:
    def test_fails_when_image_pinned_by_version_tag(self):
        cfg = """
        stages: [build]
        build_job:
          stage: build
          image: python:3.12.1-slim
          script: [pytest]
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-009")
        assert not f.passed

    def test_passes_when_image_pinned_by_digest(self):
        cfg = """
        stages: [build]
        build_job:
          stage: build
          image: python@sha256:0000000000000000000000000000000000000000000000000000000000000001
          script: [pytest]
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-009")
        assert f.passed


# ── GL-026 dangerous shell idiom ────────────────────────────────────


class TestGL026ShellEval:
    def test_fails_on_eval_of_variable(self):
        cfg = """
        stages: [build]
        build_job:
          stage: build
          image: alpine:3.19.1
          script:
            - eval "$BUILD_CMD"
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-026")
        assert not f.passed

    def test_fails_on_sh_dash_c_with_variable(self):
        cfg = """
        stages: [build]
        build_job:
          stage: build
          image: alpine:3.19.1
          script:
            - sh -c "$USER_CMD"
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-026")
        assert not f.passed

    def test_passes_when_clean(self):
        cfg = """
        stages: [build]
        build_job:
          stage: build
          image: alpine:3.19.1
          script: [make test]
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-026")
        assert f.passed


# ── GL-028 services: image pinning ──────────────────────────────────


class TestGL028ServicesPinning:
    def test_fails_on_floating_service_tag(self):
        cfg = """
        stages: [test]
        test_job:
          stage: test
          image: python@sha256:0000000000000000000000000000000000000000000000000000000000000001
          services:
            - postgres:latest
          script: [pytest]
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-028")
        assert not f.passed

    def test_fails_on_dict_service_with_floating_tag(self):
        cfg = """
        stages: [test]
        test_job:
          stage: test
          image: python@sha256:0000000000000000000000000000000000000000000000000000000000000001
          services:
            - name: redis:latest
              alias: cache
          script: [pytest]
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-028")
        assert not f.passed

    def test_passes_with_full_version_tag(self):
        cfg = """
        stages: [test]
        test_job:
          stage: test
          image: python@sha256:0000000000000000000000000000000000000000000000000000000000000001
          services:
            - postgres:16.2-alpine
          script: [pytest]
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-028")
        assert f.passed

    def test_passes_with_digest_pinned_service(self):
        cfg = """
        stages: [test]
        test_job:
          stage: test
          image: python@sha256:0000000000000000000000000000000000000000000000000000000000000001
          services:
            - postgres@sha256:0000000000000000000000000000000000000000000000000000000000000002
          script: [pytest]
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-028")
        assert f.passed

    def test_passes_when_no_services_block(self):
        cfg = """
        stages: [build]
        build_job:
          stage: build
          image: python@sha256:0000000000000000000000000000000000000000000000000000000000000001
          script: [pytest]
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-028")
        assert f.passed


# ── GL-031 OIDC audience pinning ────────────────────────────────────


class TestGL031OIDCTrust:
    def test_fails_when_id_token_missing_aud(self):
        cfg = """
        stages: [deploy]
        deploy_job:
          stage: deploy
          image: amazon/aws-cli:2.15.0
          id_tokens:
            AWS_ID_TOKEN: {}
          script:
            - aws sts assume-role-with-web-identity --web-identity-token "$AWS_ID_TOKEN"
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-031")
        assert not f.passed

    def test_fails_when_id_token_aud_is_wildcard(self):
        cfg = """
        stages: [deploy]
        deploy_job:
          stage: deploy
          image: amazon/aws-cli:2.15.0
          id_tokens:
            AWS_ID_TOKEN: { aud: '*' }
          script:
            - aws sts assume-role-with-web-identity --web-identity-token "$AWS_ID_TOKEN"
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-031")
        assert not f.passed

    def test_passes_when_id_token_aud_pinned_and_environment_set(self):
        # GL-031 requires BOTH a non-wildcard ``aud:`` AND a job-level
        # ``environment:`` binding. Audience alone closes token replay
        # but doesn't gate which refs can drive the assume-role on the
        # consumer side.
        cfg = """
        stages: [deploy]
        deploy_job:
          stage: deploy
          image: amazon/aws-cli:2.15.0
          environment: production
          id_tokens:
            AWS_ID_TOKEN: { aud: 'sts.amazonaws.com' }
          script:
            - aws sts assume-role-with-web-identity --web-identity-token "$AWS_ID_TOKEN"
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-031")
        assert f.passed

    def test_passes_when_no_id_tokens_block(self):
        cfg = """
        stages: [build]
        build_job:
          stage: build
          image: alpine:3.19.1
          script: [make]
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-031")
        assert f.passed
