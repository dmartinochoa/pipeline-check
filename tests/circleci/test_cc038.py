"""Tests for CC-038 (agentic CLI output lands without human review)."""
from __future__ import annotations

from pipeline_check.core.checks.base import Severity

from .conftest import run_check


class TestCC038AiOutputAutoland:
    def test_metadata(self) -> None:
        f = run_check("""
        jobs:
          build:
            steps:
              - run: make build
        """, "CC-038")
        assert f.check_id == "CC-038"
        assert f.severity == Severity.HIGH

    def test_fails_on_agent_plus_push_same_job(self) -> None:
        f = run_check("""
        jobs:
          autofix:
            steps:
              - run: aider --message "fix the failing tests" --yes
              - run: git push origin HEAD
        """, "CC-038")
        assert not f.passed

    def test_passes_when_agent_only_opens_pr(self) -> None:
        f = run_check("""
        jobs:
          autofix:
            steps:
              - run: aider --message "fix the failing tests"
              - run: gh pr create --fill
        """, "CC-038")
        assert f.passed

    def test_passes_on_push_without_agent(self) -> None:
        f = run_check("""
        jobs:
          release:
            steps:
              - run: npm run build
              - run: git push origin HEAD
        """, "CC-038")
        assert f.passed

    def test_passes_when_agent_and_push_in_different_jobs(self) -> None:
        # CircleCI jobs have isolated checkouts, so cross-job is not autoland.
        f = run_check("""
        jobs:
          agent-job:
            steps:
              - run: claude -p "refactor the module"
          push-job:
            steps:
              - run: git push origin HEAD
        """, "CC-038")
        assert f.passed

    def test_dry_run_push_is_ignored(self) -> None:
        f = run_check("""
        jobs:
          autofix:
            steps:
              - run: aider --message "fix tests"
              - run: git push --dry-run origin HEAD
        """, "CC-038")
        assert f.passed
