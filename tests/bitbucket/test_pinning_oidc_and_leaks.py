"""Per-rule tests for Bitbucket Pipelines pin / OIDC / leak rules:
BB-009 (pipe: pinned by version rather than sha256 digest),
BB-019 (after-script references secrets — leak risk on failure),
BB-028 (``oidc: true`` step without deployment-gated environment).

BB-001 fails floating tags at HIGH; BB-009 is the stricter
sha256 tier. BB-019 and BB-028 cover the two non-obvious leak
paths in Bitbucket Pipelines: an ``after-script`` that runs even
on step failure, and an OIDC-token request that lacks the
``deployment:`` gate Bitbucket enforces approvals on.
"""
from __future__ import annotations

from .conftest import run_check

# ── BB-009 pipe digest pinning ──────────────────────────────────────


class TestBB009DigestPinning:
    def test_fails_when_pipe_pinned_by_version_only(self):
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                script:
                  - pipe: atlassian/aws-s3-deploy:1.4.0
        """
        f = run_check(cfg, "BB-009")
        assert not f.passed

    def test_passes_when_pipe_pinned_by_digest(self):
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                script:
                  - pipe: atlassian/aws-s3-deploy@sha256:0000000000000000000000000000000000000000000000000000000000000001
        """
        f = run_check(cfg, "BB-009")
        assert f.passed


# ── BB-019 after-script secret leak ─────────────────────────────────


class TestBB019AfterScriptLeak:
    def test_fails_when_after_script_references_token(self):
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                script:
                  - make build
                after-script:
                  - 'curl --header "Authorization: Bearer $BITBUCKET_TOKEN" https://example.com/notify'
        """
        f = run_check(cfg, "BB-019")
        assert not f.passed

    def test_fails_when_after_script_references_secret_named_var(self):
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                script:
                  - make build
                after-script:
                  - 'echo "deploy key: $DEPLOY_KEY" >> log.txt'
        """
        f = run_check(cfg, "BB-019")
        assert not f.passed

    def test_passes_when_after_script_clean(self):
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                script:
                  - make build
                after-script:
                  - echo "Step complete"
        """
        f = run_check(cfg, "BB-019")
        assert f.passed

    def test_passes_when_no_after_script(self):
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                script:
                  - make build
        """
        f = run_check(cfg, "BB-019")
        assert f.passed


# ── BB-028 OIDC without deployment gate ─────────────────────────────


class TestBB028OIDCTrust:
    def test_fails_when_oidc_step_lacks_deployment(self):
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                oidc: true
                image: amazon/aws-cli:2.15.0
                script:
                  - aws s3 ls
        """
        f = run_check(cfg, "BB-028")
        assert not f.passed

    def test_passes_when_oidc_step_has_deployment(self):
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                oidc: true
                deployment: production
                image: amazon/aws-cli:2.15.0
                script:
                  - aws s3 ls
        """
        f = run_check(cfg, "BB-028")
        assert f.passed

    def test_passes_when_no_oidc_step(self):
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                script:
                  - make build
        """
        f = run_check(cfg, "BB-028")
        assert f.passed


# ── BB-029 step + service image digest pinning ──────────────────────


class TestBB029ImageDigestPinning:
    SHA = "@sha256:" + "0" * 63 + "1"

    def test_fails_on_unpinned_step_image(self):
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                image: node:20
                script:
                  - npm test
        """
        f = run_check(cfg, "BB-029")
        assert not f.passed
        assert "node:20" in f.description

    def test_fails_on_unpinned_service_image(self):
        cfg = f"""
        definitions:
          services:
            postgres:
              image: postgres:16
        pipelines:
          default:
            - step:
                max-time: 30
                image: node{self.SHA}
                services: [postgres]
                script:
                  - npm test
        """
        f = run_check(cfg, "BB-029")
        assert not f.passed
        assert "postgres" in f.description

    def test_passes_when_both_step_and_service_pinned(self):
        cfg = f"""
        definitions:
          services:
            postgres:
              image: postgres{self.SHA}
        pipelines:
          default:
            - step:
                max-time: 30
                image: node{self.SHA}
                services: [postgres]
                script:
                  - npm test
        """
        f = run_check(cfg, "BB-029")
        assert f.passed

    def test_passes_when_no_image_directive(self):
        # Step inherits the runner default; nothing to pin in the YAML.
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                script:
                  - echo hi
        """
        f = run_check(cfg, "BB-029")
        assert f.passed

    def test_handles_long_form_image_block(self):
        # Bitbucket also accepts ``image: { name: <ref>, run-as-user: N }``.
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                image:
                  name: node:20
                  run-as-user: 1001
                script:
                  - npm test
        """
        f = run_check(cfg, "BB-029")
        assert not f.passed
