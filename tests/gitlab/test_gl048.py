"""Tests for GL-048 (untrusted context reaches an agentic AI CLI)."""
from __future__ import annotations

from pipeline_check.core.checks.base import Severity

from .conftest import run_check


class TestGL048AIPromptInjection:
    def test_metadata(self):
        f = run_check("build:\n  script: [make]\n", "GL-048")
        assert f.check_id == "GL-048"
        assert f.severity == Severity.HIGH

    def test_fails_on_direct_untrusted_var_into_agent(self):
        cfg = """
        review:
          script:
            - claude -p "Review this MR $CI_MERGE_REQUEST_DESCRIPTION"
        """
        f = run_check(cfg, "GL-048")
        assert not f.passed

    def test_fails_even_when_quoted_via_variable(self):
        # Quoting / variable routing does NOT sanitize an LLM prompt.
        cfg = """
        review:
          variables:
            MR_BODY: $CI_MERGE_REQUEST_DESCRIPTION
          script:
            - claude -p "Summarize $MR_BODY"
        """
        f = run_check(cfg, "GL-048")
        assert not f.passed

    def test_fails_on_global_tainted_variable(self):
        cfg = """
        variables:
          TITLE: $CI_MERGE_REQUEST_TITLE
        review:
          script:
            - aider --message "triage $TITLE"
        """
        f = run_check(cfg, "GL-048")
        assert not f.passed

    def test_passes_on_agent_with_static_prompt(self):
        cfg = """
        review:
          script:
            - claude -p "Summarize the build log in build.txt"
        """
        f = run_check(cfg, "GL-048")
        assert f.passed

    def test_passes_when_untrusted_var_not_on_agent_line(self):
        # The untrusted echo is a separate command; the agent prompt is clean.
        cfg = """
        review:
          script:
            - echo "MR is $CI_MERGE_REQUEST_TITLE"
            - claude -p "Summarize the build log"
        """
        f = run_check(cfg, "GL-048")
        assert f.passed

    def test_passes_without_agent(self):
        cfg = """
        build:
          script:
            - echo "Building $CI_MERGE_REQUEST_TITLE"
        """
        f = run_check(cfg, "GL-048")
        assert f.passed
