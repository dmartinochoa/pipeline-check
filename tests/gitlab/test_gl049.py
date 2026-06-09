"""Tests for GL-049 (agentic CLI output lands without human review)."""
from __future__ import annotations

from pipeline_check.core.checks.base import Severity

from .conftest import run_check


class TestGL049AIOutputAutoland:
    def test_metadata(self):
        f = run_check("build:\n  script: [make]\n", "GL-049")
        assert f.check_id == "GL-049"
        assert f.severity == Severity.HIGH

    def test_fails_on_agent_plus_git_push(self):
        cfg = """
        ai-fix:
          script:
            - claude -p "fix the failing test"
            - git commit -am "ai fix"
            - git push origin HEAD:main
        """
        f = run_check(cfg, "GL-049")
        assert not f.passed

    def test_fails_on_agent_plus_glab_auto_merge(self):
        cfg = """
        ai-fix:
          script:
            - aider --message "apply the patch"
            - glab mr merge 42 --auto-merge --yes
        """
        f = run_check(cfg, "GL-049")
        assert not f.passed

    def test_fails_on_agent_plus_push_option_automerge(self):
        cfg = """
        ai-fix:
          script:
            - cursor-agent "implement the fix"
            - git push -o merge_request.merge_when_pipeline_succeeds origin HEAD
        """
        f = run_check(cfg, "GL-049")
        assert not f.passed

    def test_passes_on_agent_opening_mr_for_review(self):
        cfg = """
        ai-fix:
          script:
            - claude -p "fix the failing test"
            - glab mr create --fill --title "AI fix"
        """
        f = run_check(cfg, "GL-049")
        assert f.passed

    def test_passes_on_push_without_agent(self):
        cfg = """
        publish:
          script:
            - git push origin HEAD:main
        """
        f = run_check(cfg, "GL-049")
        assert f.passed

    def test_passes_on_agent_with_dry_run_push(self):
        cfg = """
        preview:
          script:
            - claude -p "draft the change"
            - git push --dry-run origin HEAD
        """
        f = run_check(cfg, "GL-049")
        assert f.passed
