"""Tests for GHA-103 (AI review bot on untrusted trigger) and GHA-104 (AI auto-push)."""
from __future__ import annotations

from .conftest import run_check

# -- GHA-103 ----------------------------------------------------------------


class TestGHA103AIReviewUntrustedTrigger:
    def test_fails_on_ai_action_on_prt_with_write_perms(self) -> None:
        wf = """
        name: review
        on: pull_request_target
        jobs:
          review:
            runs-on: ubuntu-latest
            permissions:
              contents: read
              pull-requests: write
            steps:
              - uses: actions/checkout@v4
              - uses: coderabbitai/ai-pr-reviewer@v1
        """
        f = run_check(wf, "GHA-103")
        assert not f.passed
        assert "coderabbitai" in f.description

    def test_fails_on_ai_cli_on_issue_comment(self) -> None:
        wf = """
        name: review
        on: issue_comment
        jobs:
          review:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - run: claude -p "review the issue"
        """
        f = run_check(wf, "GHA-103")
        assert not f.passed

    def test_fails_on_codiumai_pr_agent(self) -> None:
        wf = """
        name: review
        on: pull_request_target
        jobs:
          review:
            runs-on: ubuntu-latest
            steps:
              - uses: codiumai/pr-agent@v1
        """
        f = run_check(wf, "GHA-103")
        assert not f.passed

    def test_passes_with_environment_gate(self) -> None:
        wf = """
        name: review
        on: pull_request_target
        jobs:
          review:
            runs-on: ubuntu-latest
            environment: ai-review-approved
            permissions:
              pull-requests: write
            steps:
              - uses: coderabbitai/ai-pr-reviewer@v1
        """
        f = run_check(wf, "GHA-103")
        assert f.passed

    def test_passes_with_readonly_perms(self) -> None:
        wf = """
        name: review
        on: pull_request_target
        jobs:
          review:
            runs-on: ubuntu-latest
            permissions:
              contents: read
            steps:
              - uses: coderabbitai/ai-pr-reviewer@v1
        """
        f = run_check(wf, "GHA-103")
        assert f.passed

    def test_passes_on_pull_request_trigger(self) -> None:
        wf = """
        name: review
        on: pull_request
        jobs:
          review:
            runs-on: ubuntu-latest
            steps:
              - uses: coderabbitai/ai-pr-reviewer@v1
        """
        f = run_check(wf, "GHA-103")
        assert f.passed

    def test_passes_on_push_trigger(self) -> None:
        wf = """
        name: ci
        on: push
        jobs:
          review:
            runs-on: ubuntu-latest
            steps:
              - uses: coderabbitai/ai-pr-reviewer@v1
        """
        f = run_check(wf, "GHA-103")
        assert f.passed


# -- GHA-104 ----------------------------------------------------------------


class TestGHA104AIAutoPush:
    def test_fails_on_ai_cli_then_auto_commit_action(self) -> None:
        wf = """
        name: generate
        on: workflow_dispatch
        jobs:
          generate:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - run: claude -p "implement the feature"
              - uses: stefanzweifel/git-auto-commit-action@v5
        """
        f = run_check(wf, "GHA-104")
        assert not f.passed
        assert "claude" in f.description

    def test_fails_on_ai_cli_then_git_push(self) -> None:
        wf = """
        name: generate
        on:
          schedule:
            - cron: "0 0 * * *"
        jobs:
          generate:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - run: gemini generate-code
              - run: |
                  git add .
                  git commit -m "auto"
                  git push
        """
        f = run_check(wf, "GHA-104")
        assert not f.passed

    def test_fails_on_endbug_add_and_commit(self) -> None:
        wf = """
        name: generate
        on: workflow_dispatch
        jobs:
          generate:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - run: aider --auto "fix the bug"
              - uses: EndBug/add-and-commit@v9
        """
        f = run_check(wf, "GHA-104")
        assert not f.passed

    def test_passes_with_create_pull_request(self) -> None:
        wf = """
        name: generate
        on: workflow_dispatch
        jobs:
          generate:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - run: claude -p "implement the feature"
              - uses: peter-evans/create-pull-request@v7
        """
        f = run_check(wf, "GHA-104")
        assert f.passed

    def test_passes_with_environment_gate(self) -> None:
        wf = """
        name: generate
        on: workflow_dispatch
        jobs:
          generate:
            runs-on: ubuntu-latest
            environment: deploy-approved
            steps:
              - uses: actions/checkout@v4
              - run: claude -p "implement the feature"
              - uses: stefanzweifel/git-auto-commit-action@v5
        """
        f = run_check(wf, "GHA-104")
        assert f.passed

    def test_passes_without_ai_cli(self) -> None:
        wf = """
        name: format
        on: push
        jobs:
          format:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - run: black .
              - uses: stefanzweifel/git-auto-commit-action@v5
        """
        f = run_check(wf, "GHA-104")
        assert f.passed

    def test_passes_without_push(self) -> None:
        wf = """
        name: generate
        on: workflow_dispatch
        jobs:
          generate:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - run: claude -p "implement the feature"
              - run: echo "done"
        """
        f = run_check(wf, "GHA-104")
        assert f.passed
