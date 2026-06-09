"""Tests for BB-036 (untrusted PR context reaches an agentic AI CLI)."""
from __future__ import annotations

from pipeline_check.core.checks.base import Severity

from .conftest import run_check


class TestBB036AiPromptInjection:
    def test_metadata(self):
        f = run_check(
            "pipelines:\n  default:\n    - step:\n        script: [make]\n",
            "BB-036",
        )
        assert f.check_id == "BB-036"
        assert f.severity == Severity.HIGH

    def test_fails_on_branch_name_into_agentic_cli(self):
        cfg = """
        pipelines:
          pull-requests:
            '**':
              - step:
                  name: triage
                  script:
                    - claude -p "Triage PR from branch $BITBUCKET_BRANCH"
        """
        f = run_check(cfg, "BB-036")
        assert not f.passed

    def test_fails_on_exported_tainted_var(self):
        cfg = """
        pipelines:
          pull-requests:
            '**':
              - step:
                  script:
                    - export MSG="$BITBUCKET_PR_DESTINATION_BRANCH"
                    - gemini -p "Review $MSG"
        """
        f = run_check(cfg, "BB-036")
        assert not f.passed

    def test_passes_when_no_untrusted_context(self):
        cfg = """
        pipelines:
          pull-requests:
            '**':
              - step:
                  script:
                    - claude -p "Summarize the test results in build.txt"
        """
        f = run_check(cfg, "BB-036")
        assert f.passed

    def test_passes_when_untrusted_var_without_agentic_cli(self):
        # Branch name in a plain shell command is BB-002's job, not BB-036's.
        cfg = """
        pipelines:
          pull-requests:
            '**':
              - step:
                  script:
                    - echo "Building $BITBUCKET_BRANCH"
        """
        f = run_check(cfg, "BB-036")
        assert f.passed
