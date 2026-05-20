"""Per-rule tests for GHA-061 (App-token over-scope).

The positive fixture is the scenario-26 workflow body from
``greylag-ci/cicd-goat`` (``scenarios/26-app-token-over-scope``).
"""
from __future__ import annotations

from .conftest import run_check


class TestGHA061AppTokenScopes:
    def test_fails_on_cicd_goat_scenario_26_body(self):
        # Body lifted verbatim from
        # cicd-goat/.github/workflows/scenario-26-app-token-over-scope.yml.
        wf = """
        name: scenario-26-app-token-over-scope
        on:
          push:
            branches: [main]
        permissions:
          contents: read
        jobs:
          release:
            if: false
            runs-on: ubuntu-latest
            steps:
              - id: app-token
                uses: actions/create-github-app-token@v1
                with:
                  app-id: ${{ secrets.RELEASE_APP_ID }}
                  private-key: ${{ secrets.RELEASE_APP_KEY }}
                  owner: ${{ github.repository_owner }}
              - uses: actions/checkout@v4
                with:
                  token: ${{ steps.app-token.outputs.token }}
              - run: |
                  set -euo pipefail
                  npm version patch -m "chore: release %s"
                  git push --follow-tags
        """
        f = run_check(wf, "GHA-061")
        assert not f.passed
        assert "permissions" in f.description.lower()
        assert "create-github-app-token" in f.description

    def test_passes_when_permissions_input_is_set(self):
        wf = """
        name: ci
        on: push
        jobs:
          release:
            runs-on: ubuntu-latest
            steps:
              - id: app-token
                uses: actions/create-github-app-token@v1
                with:
                  app-id: ${{ secrets.RELEASE_APP_ID }}
                  private-key: ${{ secrets.RELEASE_APP_KEY }}
                  permissions: >-
                    {"contents":"write"}
        """
        f = run_check(wf, "GHA-061")
        assert f.passed

    def test_fails_when_permissions_input_is_empty_string(self):
        wf = """
        name: ci
        on: push
        jobs:
          release:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/create-github-app-token@v1
                with:
                  app-id: ${{ secrets.RELEASE_APP_ID }}
                  private-key: ${{ secrets.RELEASE_APP_KEY }}
                  permissions: ''
        """
        f = run_check(wf, "GHA-061")
        assert not f.passed

    def test_matches_tibdex_github_app_token(self):
        wf = """
        name: ci
        on: push
        jobs:
          release:
            runs-on: ubuntu-latest
            steps:
              - uses: tibdex/github-app-token@v2
                with:
                  app_id: ${{ secrets.APP_ID }}
                  private_key: ${{ secrets.APP_KEY }}
        """
        f = run_check(wf, "GHA-061")
        assert not f.passed
        assert "tibdex/github-app-token" in f.description

    def test_matches_peter_murray_action(self):
        wf = """
        name: ci
        on: push
        jobs:
          release:
            runs-on: ubuntu-latest
            steps:
              - uses: peter-murray/workflow-application-token-action@v3
                with:
                  application_id: ${{ secrets.APP_ID }}
                  application_private_key: ${{ secrets.APP_KEY }}
        """
        f = run_check(wf, "GHA-061")
        assert not f.passed

    def test_passes_when_no_app_token_step_present(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - run: echo hi
        """
        f = run_check(wf, "GHA-061")
        assert f.passed

    def test_passes_when_permissions_is_an_inline_yaml_mapping(self):
        # The action accepts a JSON string at runtime, but workflows
        # commonly land it as a YAML mapping under ``with:``. Either
        # form counts as 'permissions declared'.
        wf = """
        name: ci
        on: push
        jobs:
          release:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/create-github-app-token@v1
                with:
                  app-id: ${{ secrets.APP_ID }}
                  private-key: ${{ secrets.APP_KEY }}
                  permissions:
                    contents: write
                    pull-requests: write
        """
        f = run_check(wf, "GHA-061")
        assert f.passed
