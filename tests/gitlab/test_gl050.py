"""Tests for GL-050 (publish job relies on a long-lived registry token)."""
from __future__ import annotations

from pipeline_check.core.checks.base import Severity

from .conftest import run_check


class TestGL050PublishLongLivedToken:
    def test_metadata(self):
        f = run_check("build:\n  script: [make]\n", "GL-050")
        assert f.check_id == "GL-050"
        assert f.severity == Severity.HIGH

    def test_fails_on_npm_publish_with_npm_token(self):
        cfg = """
        publish:
          stage: deploy
          script:
            - echo "//registry.npmjs.org/:_authToken=${NPM_TOKEN}" > .npmrc
            - npm publish
        """
        f = run_check(cfg, "GL-050")
        assert not f.passed

    def test_fails_on_twine_upload_with_twine_password(self):
        cfg = """
        release:
          script:
            - twine upload dist/*
          variables:
            TWINE_PASSWORD: $PYPI_SECRET
        """
        f = run_check(cfg, "GL-050")
        assert not f.passed

    def test_fails_when_token_only_in_global_variables(self):
        cfg = """
        variables:
          NODE_AUTH_TOKEN: $CI_NPM_SECRET
        publish:
          script: [npm publish]
        """
        f = run_check(cfg, "GL-050")
        assert not f.passed

    def test_passes_on_oidc_trusted_publishing(self):
        cfg = """
        publish:
          id_tokens:
            NPM_ID_TOKEN:
              aud: https://registry.npmjs.org
          script: [npm publish]
        """
        f = run_check(cfg, "GL-050")
        assert f.passed

    def test_passes_on_ci_job_token_native_path(self):
        # CI_JOB_TOKEN is GitLab's built-in per-job token for the project's
        # own Package Registry; it is not a long-lived external credential.
        cfg = """
        publish:
          script:
            - echo "//${CI_SERVER_HOST}/api/v4/projects/${CI_PROJECT_ID}/packages/npm/:_authToken=${CI_JOB_TOKEN}" > .npmrc
            - npm publish
        """
        f = run_check(cfg, "GL-050")
        assert f.passed

    def test_passes_when_no_publish_verb(self):
        cfg = """
        build:
          script:
            - npm pack
          variables:
            NPM_TOKEN: $SECRET
        """
        f = run_check(cfg, "GL-050")
        assert f.passed

    def test_passes_when_publish_without_long_lived_token(self):
        cfg = """
        publish:
          script: [cargo publish]
        """
        f = run_check(cfg, "GL-050")
        assert f.passed
