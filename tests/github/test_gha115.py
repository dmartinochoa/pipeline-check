"""Per-rule tests for GHA-115 (workflow-wide id-token: write).

Fires when ``id-token: write`` sits on the top-level ``permissions:``
block but only a subset of jobs consume the OIDC token, so the
inheriting non-consumers carry a publish-capable mint right they never
use. Pairs with GHA-069 (granted-but-unused).
"""
from __future__ import annotations

from .conftest import run_check


class TestGHA115WorkflowWideIdToken:
    def test_fails_when_build_inherits_but_only_publish_consumes(self):
        wf = """
        permissions:
          contents: read
          id-token: write
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: npm ci --ignore-scripts && npm run build
          publish:
            needs: build
            runs-on: ubuntu-latest
            steps:
              - uses: pypa/gh-action-pypi-publish@v1
        """
        f = run_check(wf, "GHA-115")
        assert not f.passed
        assert f.job_anchors == ("build",)

    def test_fails_on_write_all_top_level(self):
        wf = """
        permissions: write-all
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: pytest
          deploy:
            runs-on: ubuntu-latest
            steps:
              - uses: aws-actions/configure-aws-credentials@v4
                with:
                  role-to-assume: arn:aws:iam::123:role/x
        """
        f = run_check(wf, "GHA-115")
        assert not f.passed
        assert f.job_anchors == ("test",)

    def test_passes_when_every_inheriting_job_consumes(self):
        wf = """
        permissions:
          id-token: write
        jobs:
          publish-npm:
            runs-on: ubuntu-latest
            steps:
              - uses: pypa/gh-action-pypi-publish@v1
          sign:
            runs-on: ubuntu-latest
            steps:
              - uses: sigstore/cosign-installer@v3
        """
        assert run_check(wf, "GHA-115").passed

    def test_passes_when_no_job_consumes_gha069_territory(self):
        # Top-level grant, but no consumer anywhere -> orphan, GHA-069's
        # case, not the over-broad case GHA-115 targets.
        wf = """
        permissions:
          id-token: write
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: ./build.sh
        """
        assert run_check(wf, "GHA-115").passed

    def test_passes_when_id_token_is_job_scoped(self):
        # Already least-privilege: only the publish job declares it.
        wf = """
        permissions:
          contents: read
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: npm run build
          publish:
            runs-on: ubuntu-latest
            permissions:
              id-token: write
            steps:
              - uses: pypa/gh-action-pypi-publish@v1
        """
        assert run_check(wf, "GHA-115").passed

    def test_passes_when_nonconsumer_overrides_permissions(self):
        # The build job scopes itself out with its own permissions block,
        # so it does not inherit the workflow-level id-token.
        wf = """
        permissions:
          id-token: write
        jobs:
          build:
            runs-on: ubuntu-latest
            permissions:
              contents: read
            steps:
              - run: ./build.sh
          publish:
            runs-on: ubuntu-latest
            steps:
              - uses: pypa/gh-action-pypi-publish@v1
        """
        assert run_check(wf, "GHA-115").passed

    def test_anchors_all_over_broad_jobs(self):
        wf = """
        permissions:
          id-token: write
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: make build
          test:
            runs-on: ubuntu-latest
            steps:
              - run: make test
          publish:
            runs-on: ubuntu-latest
            steps:
              - uses: pypa/gh-action-pypi-publish@v1
        """
        f = run_check(wf, "GHA-115")
        assert not f.passed
        assert set(f.job_anchors) == {"build", "test"}
