"""Tests for ADO-038 (agentic CLI output lands without human review)."""
from __future__ import annotations

from pipeline_check.core.checks.base import Severity

from .conftest import run_check


class TestADO038AiOutputAutoland:
    def test_metadata(self) -> None:
        f = run_check("steps:\n  - script: make\n", "ADO-038")
        assert f.check_id == "ADO-038"
        assert f.severity == Severity.HIGH

    def test_fails_on_agent_then_git_push_across_steps(self) -> None:
        # Steps of one Azure job share a checkout, so an agent in one step
        # and a push in a later step are coupled.
        f = run_check("""
        jobs:
          - job: AiFix
            steps:
              - script: claude -p "Fix the failing test"
              - script: git push origin HEAD
        """, "ADO-038")
        assert not f.passed
        assert "git push" in f.description

    def test_fails_on_az_repos_auto_complete(self) -> None:
        f = run_check("""
        jobs:
          - job: AiFix
            steps:
              - bash: |
                  aider --message "apply the fix"
                  az repos pr create --auto-complete true
        """, "ADO-038")
        assert not f.passed

    def test_passes_when_agent_only_opens_pr(self) -> None:
        f = run_check("""
        jobs:
          - job: AiTriage
            steps:
              - script: az repos pr create --title "AI fix"
              - script: claude -p "Summarize the change"
        """, "ADO-038")
        assert f.passed

    def test_passes_on_git_push_without_agent(self) -> None:
        f = run_check("""
        jobs:
          - job: Format
            steps:
              - script: npm run format
              - script: git push origin HEAD
        """, "ADO-038")
        assert f.passed

    def test_passes_on_dry_run_push(self) -> None:
        f = run_check("""
        jobs:
          - job: AiFix
            steps:
              - script: goose run "suggest a fix"
              - script: git push --dry-run origin HEAD
        """, "ADO-038")
        assert f.passed
