"""Tests for BB-039 (agentic CLI output lands without human review)."""
from __future__ import annotations

from pipeline_check.core.checks.base import Severity

from .conftest import run_check


class TestBB039AiOutputAutoland:
    def test_metadata(self):
        f = run_check(
            "pipelines:\n  default:\n    - step:\n        script: [make]\n",
            "BB-039",
        )
        assert f.check_id == "BB-039"
        assert f.severity == Severity.HIGH

    def test_fails_on_agent_then_git_push(self):
        cfg = """
        pipelines:
          default:
            - step:
                name: ai fix
                script:
                  - claude -p "Fix the failing test and commit"
                  - git push origin HEAD
        """
        f = run_check(cfg, "BB-039")
        assert not f.passed
        assert "git push" in f.description

    def test_passes_when_agent_only_opens_pr(self):
        cfg = """
        pipelines:
          default:
            - step:
                script:
                  - aider --message "open a PR with the fix"
        """
        f = run_check(cfg, "BB-039")
        assert f.passed

    def test_passes_on_git_push_without_agent(self):
        cfg = """
        pipelines:
          default:
            - step:
                script:
                  - npm run format
                  - git push origin HEAD
        """
        f = run_check(cfg, "BB-039")
        assert f.passed

    def test_passes_on_dry_run_push(self):
        cfg = """
        pipelines:
          default:
            - step:
                script:
                  - claude -p "Suggest a fix"
                  - git push --dry-run origin HEAD
        """
        f = run_check(cfg, "BB-039")
        assert f.passed

    def test_passes_when_agent_and_push_in_separate_steps(self):
        # Each Bitbucket step is an isolated container with a fresh clone,
        # so an agent in one step and a push in another are not coupled.
        cfg = """
        pipelines:
          default:
            - step:
                script:
                  - claude -p "Fix the bug"
            - step:
                script:
                  - git push origin HEAD
        """
        f = run_check(cfg, "BB-039")
        assert f.passed
