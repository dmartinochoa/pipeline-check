"""Tests for ADO-035 (untrusted PR context reaches an agentic AI CLI)."""
from __future__ import annotations

from pipeline_check.core.checks.base import Severity

from .conftest import run_check


class TestADO035AiPromptInjection:
    def test_metadata(self) -> None:
        f = run_check("steps:\n  - script: make\n", "ADO-035")
        assert f.check_id == "ADO-035"
        assert f.severity == Severity.HIGH

    def test_fails_on_commit_message_into_agentic_cli(self) -> None:
        f = run_check("""
        steps:
          - script: claude -p "Triage this PR from commit $(Build.SourceVersionMessage)"
        """, "ADO-035")
        assert not f.passed

    def test_fails_on_pr_source_branch_in_bash(self) -> None:
        f = run_check("""
        steps:
          - bash: |
              gemini -p "Review $(System.PullRequest.SourceBranch)"
        """, "ADO-035")
        assert not f.passed

    def test_fails_via_tainted_variable_reference(self) -> None:
        f = run_check("""
        variables:
          MSG: $(Build.SourceVersionMessage)
        steps:
          - script: claude -p "Summarize $(MSG)"
        """, "ADO-035")
        assert not f.passed

    def test_passes_when_no_untrusted_context(self) -> None:
        f = run_check("""
        steps:
          - script: claude -p "Summarize the test results in build.txt"
        """, "ADO-035")
        assert f.passed

    def test_passes_when_untrusted_var_without_agentic_cli(self) -> None:
        # Macro in a plain shell command is ADO-002's job, not ADO-035's.
        f = run_check("""
        steps:
          - script: echo "Building $(Build.SourceBranch)"
        """, "ADO-035")
        assert f.passed
