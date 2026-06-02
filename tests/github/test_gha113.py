"""Per-rule tests for GHA-113 (OIDC trusted-publishing job, no env gate).

The headline case is the Red Hat npm "untrusted branch" shape: a job
grants ``id-token: write`` and publishes a package with no
``environment:`` binding, so the OIDC token mints from any branch that
runs the workflow.
"""
from __future__ import annotations

from .conftest import run_check


class TestGHA113OidcPublishEnvironment:
    def test_fails_on_npm_trusted_publish_without_environment(self):
        wf = """
        on:
          push:
            branches: [main]
        jobs:
          release:
            runs-on: ubuntu-latest
            permissions:
              contents: read
              id-token: write
            steps:
              - uses: actions/checkout@v4
              - run: npm ci --ignore-scripts
              - run: npm publish --provenance --access public
        """
        f = run_check(wf, "GHA-113")
        assert not f.passed
        assert "release" in f.description
        assert f.job_anchors == ("release",)

    def test_fails_on_pypi_trusted_publisher_action(self):
        wf = """
        permissions:
          id-token: write
        jobs:
          publish:
            runs-on: ubuntu-latest
            steps:
              - uses: pypa/gh-action-pypi-publish@release/v1
        """
        assert not run_check(wf, "GHA-113").passed

    def test_fails_on_job_level_id_token(self):
        wf = """
        jobs:
          release:
            runs-on: ubuntu-latest
            permissions:
              id-token: write
            steps:
              - run: cargo publish
        """
        assert not run_check(wf, "GHA-113").passed

    def test_fails_on_write_all(self):
        wf = """
        permissions: write-all
        jobs:
          release:
            runs-on: ubuntu-latest
            steps:
              - uses: rubygems/release-gem@v1
        """
        assert not run_check(wf, "GHA-113").passed

    def test_passes_when_environment_bound(self):
        wf = """
        on:
          push:
            tags: ['v*']
        jobs:
          release:
            runs-on: ubuntu-latest
            environment: npm-publish
            permissions:
              contents: read
              id-token: write
            steps:
              - run: npm publish --provenance
        """
        assert run_check(wf, "GHA-113").passed

    def test_passes_when_environment_long_form(self):
        wf = """
        jobs:
          release:
            runs-on: ubuntu-latest
            environment:
              name: npm-publish
              url: https://www.npmjs.com/package/x
            permissions:
              id-token: write
            steps:
              - run: npm publish
        """
        assert run_check(wf, "GHA-113").passed

    def test_passes_without_id_token(self):
        # No OIDC token: this is the long-lived-token lane GHA-050 owns,
        # not GHA-113.
        wf = """
        jobs:
          release:
            runs-on: ubuntu-latest
            steps:
              - run: npm publish
                env:
                  NODE_AUTH_TOKEN: token-here
        """
        assert run_check(wf, "GHA-113").passed

    def test_passes_when_id_token_but_no_publish_step(self):
        # id-token for a cloud-credentials exchange, no package publish.
        wf = """
        permissions:
          id-token: write
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - uses: aws-actions/configure-aws-credentials@v4
                with:
                  role-to-assume: arn:aws:iam::123:role/x
        """
        assert run_check(wf, "GHA-113").passed

    def test_job_level_permissions_override_workflow(self):
        # Workflow grants id-token: write; the publish job replaces it
        # with a read-only set, so it no longer mints a token.
        wf = """
        permissions:
          id-token: write
        jobs:
          release:
            runs-on: ubuntu-latest
            permissions:
              contents: read
            steps:
              - run: npm publish
        """
        assert run_check(wf, "GHA-113").passed

    def test_lookalike_publisher_action_does_not_count(self):
        # A typo-squatted publisher repo is not the real trusted
        # publisher, so without a recognized publish step the job has
        # an orphan token (GHA-069's concern), not a GHA-113 finding.
        wf = """
        permissions:
          id-token: write
        jobs:
          publish:
            runs-on: ubuntu-latest
            steps:
              - uses: pypa/gh-action-pypi-publish-malicious@v1
        """
        assert run_check(wf, "GHA-113").passed

    def test_multiple_publish_steps_one_finding_per_step(self):
        wf = """
        permissions:
          id-token: write
        jobs:
          release:
            runs-on: ubuntu-latest
            steps:
              - run: npm publish
              - run: pnpm publish
        """
        f = run_check(wf, "GHA-113")
        assert not f.passed
        assert "2 publish step(s)" in f.description
        assert f.job_anchors == ("release",)
