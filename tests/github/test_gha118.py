"""Tests for GHA-118 (untrusted content into $GITHUB_ENV / $GITHUB_PATH)."""
from __future__ import annotations

from .conftest import run_check


class TestGHA118GithubEnvInjection:
    def test_fails_on_pr_target_file_into_github_env(self):
        wf = """
        on: pull_request_target
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: cat ./ci.env >> "$GITHUB_ENV"
        """
        f = run_check(wf, "GHA-118")
        assert not f.passed
        assert "GITHUB_ENV" in f.description

    def test_fails_on_command_substitution_file_read(self):
        wf = """
        on: pull_request
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - run: echo "$(cat ./payload)" >> $GITHUB_ENV
        """
        f = run_check(wf, "GHA-118")
        assert not f.passed

    def test_fails_on_hijack_key_dynamic_value(self):
        wf = """
        on: pull_request_target
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - run: echo "LD_PRELOAD=$EVIL" >> $GITHUB_ENV
        """
        f = run_check(wf, "GHA-118")
        assert not f.passed

    def test_fails_on_file_into_github_path(self):
        wf = """
        on: workflow_run
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - run: cat ./bindir >> $GITHUB_PATH
        """
        f = run_check(wf, "GHA-118")
        assert not f.passed

    def test_passes_on_fixed_literal(self):
        wf = """
        on: pull_request_target
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - run: echo "BUILD_PROFILE=ci" >> "$GITHUB_ENV"
        """
        f = run_check(wf, "GHA-118")
        assert f.passed

    def test_passes_on_git_describe_into_benign_key(self):
        # A command substitution that isn't a file/tool read of repo
        # content, into a benign key, is the common release pattern.
        wf = """
        on: pull_request
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - run: echo "VER=$(git describe --tags)" >> $GITHUB_ENV
        """
        f = run_check(wf, "GHA-118")
        assert f.passed

    def test_passes_on_trusted_push_trigger(self):
        # On a trusted trigger the workspace content is the repo's own,
        # not attacker-influenced, so the env-file write is not injection.
        wf = """
        on: push
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - run: cat ./ci.env >> $GITHUB_ENV
        """
        f = run_check(wf, "GHA-118")
        assert f.passed

    def test_passes_on_static_node_options(self):
        wf = """
        on: pull_request
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - run: echo "NODE_OPTIONS=--max-old-space-size=4096" >> $GITHUB_ENV
        """
        f = run_check(wf, "GHA-118")
        assert f.passed
