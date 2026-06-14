"""Tests for CC-037 (untrusted context reaches an agentic AI CLI)."""
from __future__ import annotations

from pipeline_check.core.checks.base import Severity

from .conftest import run_check


class TestCC037AiPromptInjection:
    def test_metadata(self) -> None:
        f = run_check("""
        jobs:
          triage:
            steps:
              - run: make build
        """, "CC-037")
        assert f.check_id == "CC-037"
        assert f.severity == Severity.HIGH

    def test_fails_on_agent_with_circle_branch(self) -> None:
        f = run_check("""
        jobs:
          triage:
            steps:
              - run: claude -p "Triage branch $CIRCLE_BRANCH"
        """, "CC-037")
        assert not f.passed

    def test_fails_on_agent_with_pipeline_git_interpolation(self) -> None:
        f = run_check("""
        jobs:
          triage:
            steps:
              - run: aider --message "Review << pipeline.git.tag >>"
        """, "CC-037")
        assert not f.passed

    def test_passes_on_agent_without_untrusted_context(self) -> None:
        f = run_check("""
        jobs:
          triage:
            steps:
              - run: claude -p "Summarize the build log and suggest fixes"
        """, "CC-037")
        assert f.passed

    def test_passes_on_untrusted_context_without_agent(self) -> None:
        # Untrusted env in a plain build command is CC-002 territory.
        f = run_check("""
        jobs:
          build:
            steps:
              - run: ./build.sh --branch $CIRCLE_BRANCH
        """, "CC-037")
        assert f.passed

    def test_passes_on_pipeline_parameter(self) -> None:
        f = run_check("""
        jobs:
          triage:
            steps:
              - run: claude -p "Deploy << pipeline.parameters.target >>"
        """, "CC-037")
        assert f.passed
