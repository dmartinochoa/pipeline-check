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


# ── GL-032 tags injection ───────────────────────────────────────────


class TestGL032TagsInjection:
    def test_fails_on_commit_ref_name_in_tags(self):
        # ``$CI_COMMIT_REF_NAME`` is the branch / tag the pusher
        # picked — letting it pick the runner is a self-managed
        # foothold attack identical to GHA-036's reusable-workflow
        # caller scenario.
        cfg = """
        stages: [build]
        build_job:
          stage: build
          image: alpine:3.19.1
          tags: [$CI_COMMIT_REF_NAME]
          script: [make]
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-032")
        assert not f.passed
        assert "build_job" in f.description

    def test_fails_on_braced_commit_message(self):
        cfg = """
        stages: [build]
        build_job:
          stage: build
          image: alpine:3.19.1
          tags: ["${CI_COMMIT_MESSAGE}", "self-managed"]
          script: [make]
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-032")
        assert not f.passed

    def test_fails_on_merge_request_title(self):
        cfg = """
        stages: [build]
        build_job:
          stage: build
          image: alpine:3.19.1
          tags: ["$CI_MERGE_REQUEST_TITLE"]
          script: [make]
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-032")
        assert not f.passed

    def test_fails_on_string_tag_form(self):
        # ``tags:`` accepts a single string scalar in addition to the
        # canonical list form. Same threat surface.
        cfg = """
        stages: [build]
        build_job:
          stage: build
          image: alpine:3.19.1
          tags: $CI_COMMIT_BRANCH
          script: [make]
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-032")
        assert not f.passed

    def test_passes_on_static_tag_list(self):
        cfg = """
        stages: [build]
        build_job:
          stage: build
          image: alpine:3.19.1
          tags: [self-managed, ephemeral, deploy-prod]
          script: [make]
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-032")
        assert f.passed

    def test_passes_on_custom_static_variable(self):
        # ``$DEPLOY_FLEET`` is author-controlled — defined in the
        # workflow's own ``variables:`` block, not from SCM event
        # metadata. The rule only matches the curated catalog of
        # untrusted predefined CI variables.
        cfg = """
        stages: [build]
        variables:
          DEPLOY_FLEET: prod-fleet
        build_job:
          stage: build
          image: alpine:3.19.1
          tags: [$DEPLOY_FLEET]
          script: [make]
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-032")
        assert f.passed

    def test_passes_when_no_tags_set(self):
        # No ``tags:`` means the GitLab default runner pool — out of
        # scope for this rule (GL-014 covers that).
        cfg = """
        stages: [build]
        build_job:
          stage: build
          image: alpine:3.19.1
          script: [make]
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-032")
        assert f.passed


# ── GL-033 global before_script / after_script taint ─────────────────


class TestGL033GlobalScriptTaint:
    def test_passes_with_safe_global_before_script(self):
        cfg = """
        stages: [build]
        before_script:
          - echo "Static banner"
        build_job:
          stage: build
          image: alpine:3.19.1
          script: [make]
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-033")
        assert f.passed

    def test_fails_when_root_before_script_uses_commit_title(self):
        cfg = """
        stages: [build]
        before_script:
          - echo Building ${CI_COMMIT_TITLE}
        build_job:
          stage: build
          image: alpine:3.19.1
          script: [make]
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-033")
        assert not f.passed
        assert "before_script" in f.description
        assert "CI_COMMIT_TITLE" in f.description

    def test_fails_when_default_before_script_uses_mr_title(self):
        cfg = """
        stages: [build]
        default:
          before_script:
            - echo MR ${CI_MERGE_REQUEST_TITLE}
        build_job:
          stage: build
          image: alpine:3.19.1
          script: [make]
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-033")
        assert not f.passed
        assert "default.before_script" in f.description

    def test_fails_when_root_after_script_uses_commit_message(self):
        cfg = """
        stages: [build]
        after_script:
          - logger -p user.notice "Build for $CI_COMMIT_MESSAGE finished"
        build_job:
          stage: build
          image: alpine:3.19.1
          script: [make]
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-033")
        assert not f.passed
        assert "after_script" in f.description

    def test_passes_when_no_global_scripts_declared(self):
        cfg = """
        stages: [build]
        build_job:
          stage: build
          image: alpine:3.19.1
          script: [make]
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-033")
        assert f.passed

    def test_fails_on_string_form_of_before_script(self):
        # ``before_script:`` accepts a single-string scalar form
        # alongside the list form; both are flattened to lines.
        cfg = """
        stages: [build]
        before_script: 'echo Building $CI_COMMIT_REF_NAME'
        build_job:
          stage: build
          image: alpine:3.19.1
          script: [make]
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-033")
        assert not f.passed
