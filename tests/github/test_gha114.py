"""Per-rule tests for GHA-114 (publish workflow on an unrestricted push trigger).

The headline case is the Red Hat npm "untrusted branch" shape: a
workflow that publishes a package is reachable from ``on: push`` to any
branch, so a counterfeit copy on a throwaway branch runs the publish
path. Tag / dispatch / release triggers and exact branch lists pass.
"""
from __future__ import annotations

from .conftest import run_check


class TestGHA114PublishUnrestrictedTrigger:
    def test_fails_on_unfiltered_push_publish(self):
        wf = """
        on:
          push:
        jobs:
          release:
            runs-on: ubuntu-latest
            steps:
              - run: npm ci --ignore-scripts
              - run: npm publish --provenance --access public
        """
        f = run_check(wf, "GHA-114")
        assert not f.passed
        assert f.job_anchors == ("release",)

    def test_fails_on_bare_on_push_string(self):
        # ``on: push`` (scalar) parses to the boolean True key in YAML 1.1.
        wf = """
        on: push
        jobs:
          release:
            runs-on: ubuntu-latest
            steps:
              - run: cargo publish
        """
        assert not run_check(wf, "GHA-114").passed

    def test_fails_on_wildcard_branches_publish(self):
        wf = """
        on:
          push:
            branches: ['release/*']
        jobs:
          publish:
            runs-on: ubuntu-latest
            steps:
              - run: twine upload dist/*
        """
        f = run_check(wf, "GHA-114")
        assert not f.passed
        assert f.job_anchors == ("publish",)

    def test_fails_on_pypi_action_unrestricted(self):
        wf = """
        on:
          push:
            branches: ['*']
        jobs:
          publish:
            runs-on: ubuntu-latest
            steps:
              - uses: pypa/gh-action-pypi-publish@release/v1
        """
        assert not run_check(wf, "GHA-114").passed

    def test_fails_on_branches_ignore_without_branches(self):
        # branches-ignore restricts nothing the attacker needs: any
        # non-ignored branch still fires the publish.
        wf = """
        on:
          push:
            branches-ignore: [docs]
        jobs:
          release:
            runs-on: ubuntu-latest
            steps:
              - run: pnpm publish
        """
        assert not run_check(wf, "GHA-114").passed

    def test_passes_on_tag_only_push(self):
        wf = """
        on:
          push:
            tags: ['v*']
        jobs:
          release:
            runs-on: ubuntu-latest
            steps:
              - run: npm publish --provenance
        """
        assert run_check(wf, "GHA-114").passed

    def test_passes_on_exact_branch(self):
        wf = """
        on:
          push:
            branches: [main]
        jobs:
          release:
            runs-on: ubuntu-latest
            steps:
              - run: npm publish
        """
        assert run_check(wf, "GHA-114").passed

    def test_passes_on_exact_branch_with_tags(self):
        wf = """
        on:
          push:
            branches: [main, master]
            tags: ['v*']
        jobs:
          release:
            runs-on: ubuntu-latest
            steps:
              - run: gem push pkg/x.gem
        """
        assert run_check(wf, "GHA-114").passed

    def test_passes_on_workflow_dispatch_only(self):
        wf = """
        on:
          workflow_dispatch:
        jobs:
          release:
            runs-on: ubuntu-latest
            steps:
              - run: npm publish
        """
        assert run_check(wf, "GHA-114").passed

    def test_passes_on_release_published(self):
        wf = """
        on:
          release:
            types: [published]
        jobs:
          release:
            runs-on: ubuntu-latest
            steps:
              - uses: rubygems/release-gem@v1
        """
        assert run_check(wf, "GHA-114").passed

    def test_passes_when_no_publish_step(self):
        # Unrestricted push, but the workflow only builds/tests; nothing
        # publishes, so there is no untrusted-branch publish exposure.
        wf = """
        on:
          push:
        jobs:
          ci:
            runs-on: ubuntu-latest
            steps:
              - run: npm ci
              - run: npm test
        """
        assert run_check(wf, "GHA-114").passed

    def test_lookalike_publisher_action_does_not_count(self):
        wf = """
        on:
          push:
        jobs:
          publish:
            runs-on: ubuntu-latest
            steps:
              - uses: pypa/gh-action-pypi-publish-malicious@v1
        """
        assert run_check(wf, "GHA-114").passed
