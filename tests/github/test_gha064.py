"""Per-rule tests for GHA-064 (unsound contains with comma string)."""
from __future__ import annotations

from .conftest import run_check


class TestGHA064UnsoundContains:
    def test_fails_on_comma_list_string(self):
        wf = """
        on: push
        jobs:
          deploy:
            if: contains('main, develop, release', github.ref_name)
            runs-on: ubuntu-latest
            steps: [{run: ./deploy.sh}]
        """
        f = run_check(wf, "GHA-064")
        assert not f.passed
        assert "main, develop" in f.description

    def test_fails_on_double_quoted_string(self):
        wf = """
        on: push
        jobs:
          deploy:
            if: contains("main, develop", github.ref_name)
            runs-on: ubuntu-latest
            steps: [{run: echo}]
        """
        assert not run_check(wf, "GHA-064").passed

    def test_fails_on_release_hotfix_pattern(self):
        wf = """
        on: pull_request
        jobs:
          gate:
            if: contains('release/, hotfix/', github.head_ref)
            runs-on: ubuntu-latest
            steps: [{run: echo}]
        """
        assert not run_check(wf, "GHA-064").passed

    def test_passes_on_from_json_array(self):
        wf = """
        on: push
        jobs:
          deploy:
            if: contains(fromJSON('["main", "develop"]'), github.ref_name)
            runs-on: ubuntu-latest
            steps: [{run: echo}]
        """
        assert run_check(wf, "GHA-064").passed

    def test_passes_on_no_comma_substring(self):
        # ``contains('refs/heads/release', github.ref)`` is a genuine
        # substring / prefix check, not the list-confusion bug shape.
        wf = """
        on: push
        jobs:
          deploy:
            if: contains('refs/heads/release', github.ref)
            runs-on: ubuntu-latest
            steps: [{run: echo}]
        """
        assert run_check(wf, "GHA-064").passed

    def test_passes_on_explicit_or(self):
        wf = """
        on: push
        jobs:
          deploy:
            if: github.ref_name == 'main' || github.ref_name == 'develop'
            runs-on: ubuntu-latest
            steps: [{run: echo}]
        """
        assert run_check(wf, "GHA-064").passed

    def test_step_level_predicate(self):
        wf = """
        on: push
        jobs:
          x:
            runs-on: ubuntu-latest
            steps:
              - if: contains('main, develop', github.ref_name)
                run: echo
        """
        f = run_check(wf, "GHA-064")
        assert not f.passed
        assert "steps[0]" in f.description

    def test_passes_when_no_contains(self):
        wf = """
        on: push
        jobs:
          x:
            runs-on: ubuntu-latest
            steps: [{run: echo}]
        """
        assert run_check(wf, "GHA-064").passed
