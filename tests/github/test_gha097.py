"""Tests for GHA-097: recursive PR auto-merge loop."""
from __future__ import annotations

from .conftest import run_check


class TestGHA097:
    def test_fires_on_pr_create_and_automerge(self) -> None:
        wf = """
        name: update
        on: pull_request
        jobs:
          update:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@abc123
              - uses: peter-evans/create-pull-request@abc123
              - run: gh pr merge --auto --squash
        """
        f = run_check(wf, "GHA-097")
        assert not f.passed
        assert "loop" in f.description.lower()

    def test_fires_on_pr_target_with_cli_create(self) -> None:
        wf = """
        name: update
        on: pull_request_target
        jobs:
          update:
            runs-on: ubuntu-latest
            steps:
              - run: gh pr create --title "chore"
              - run: gh pr merge --auto --squash
        """
        f = run_check(wf, "GHA-097")
        assert not f.passed

    def test_passes_on_push_trigger(self) -> None:
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: echo hello
        """
        f = run_check(wf, "GHA-097")
        assert f.passed

    def test_passes_on_pr_trigger_without_automerge(self) -> None:
        wf = """
        name: ci
        on: pull_request
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@abc123
              - run: make test
        """
        f = run_check(wf, "GHA-097")
        assert f.passed

    def test_passes_on_pr_trigger_create_only(self) -> None:
        wf = """
        name: update
        on: pull_request
        jobs:
          update:
            runs-on: ubuntu-latest
            steps:
              - uses: peter-evans/create-pull-request@abc123
        """
        f = run_check(wf, "GHA-097")
        assert f.passed
