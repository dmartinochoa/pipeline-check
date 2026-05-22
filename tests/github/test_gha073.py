"""Per-rule tests for GHA-073 (unused workflow_call.secrets)."""
from __future__ import annotations

from .conftest import run_check


class TestGHA073UnusedWorkflowCallSecret:
    def test_fails_on_unused_required_secret(self):
        wf = """
        on:
          workflow_call:
            secrets:
              DEPLOY_TOKEN:
                required: true
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: './build.sh'
        """
        f = run_check(wf, "GHA-073")
        assert not f.passed
        assert "DEPLOY_TOKEN" in f.description

    def test_passes_on_referenced_in_step_env(self):
        wf = """
        on:
          workflow_call:
            secrets:
              DEPLOY_TOKEN:
                required: true
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - env:
                  DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}
                run: './deploy.sh'
        """
        assert run_check(wf, "GHA-073").passed

    def test_passes_on_referenced_in_run_body(self):
        wf = """
        on:
          workflow_call:
            secrets:
              NPM_TOKEN:
                required: true
        jobs:
          publish:
            runs-on: ubuntu-latest
            steps:
              - run: 'echo //registry.npmjs.org/:_authToken=${{ secrets.NPM_TOKEN }} > .npmrc'
        """
        assert run_check(wf, "GHA-073").passed

    def test_passes_on_workflow_without_call_trigger(self):
        wf = """
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: './build.sh'
        """
        assert run_check(wf, "GHA-073").passed

    def test_partial_unused_with_one_used(self):
        wf = """
        on:
          workflow_call:
            secrets:
              USED:
                required: true
              UNUSED:
                required: true
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - env:
                  X: ${{ secrets.USED }}
                run: './build.sh'
        """
        f = run_check(wf, "GHA-073")
        assert not f.passed
        assert "UNUSED" in f.description
        assert "USED," not in f.description  # 'USED' isn't in the unused list

    def test_passes_on_optional_secret_used(self):
        wf = """
        on:
          workflow_call:
            secrets:
              GH_PAT:
                required: false
        jobs:
          publish:
            runs-on: ubuntu-latest
            steps:
              - run: 'gh release create --notes "ok"'
                env:
                  GITHUB_TOKEN: ${{ secrets.GH_PAT }}
        """
        assert run_check(wf, "GHA-073").passed

    def test_partial_name_not_matched(self):
        # ``secrets.GH_PAT_NEW`` doesn't satisfy ``secrets.GH_PAT``.
        wf = """
        on:
          workflow_call:
            secrets:
              GH_PAT:
                required: true
        jobs:
          publish:
            runs-on: ubuntu-latest
            steps:
              - run: 'gh release create'
                env:
                  GITHUB_TOKEN: ${{ secrets.GH_PAT_NEW }}
        """
        assert not run_check(wf, "GHA-073").passed

    def test_passes_on_no_secrets_block(self):
        wf = """
        on:
          workflow_call:
            inputs:
              version:
                type: string
        jobs:
          build:
            runs-on: ubuntu-latest
            steps: [{run: echo}]
        """
        assert run_check(wf, "GHA-073").passed
