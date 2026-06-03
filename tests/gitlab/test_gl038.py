"""Tests for GL-038 (CI_DEBUG_TRACE / debug logging dumps secrets to log)."""
from __future__ import annotations

from .conftest import run_check


class TestGL038DebugTrace:
    def test_fails_on_global_ci_debug_trace_string_true(self) -> None:
        f = run_check("""
        variables:
          CI_DEBUG_TRACE: "true"
        build:
          script:
            - make build
        """, "GL-038")
        assert not f.passed
        assert "CI_DEBUG_TRACE" in f.description

    def test_fails_on_unquoted_bool_true(self) -> None:
        f = run_check("""
        variables:
          CI_DEBUG_TRACE: true
        build:
          script: [make]
        """, "GL-038")
        assert not f.passed

    def test_fails_on_job_level_debug_trace(self) -> None:
        f = run_check("""
        build:
          variables:
            CI_DEBUG_TRACE: "1"
          script: [make]
        """, "GL-038")
        assert not f.passed

    def test_fails_on_ci_debug_services(self) -> None:
        f = run_check("""
        variables:
          CI_DEBUG_SERVICES: "true"
        build:
          script: [make]
        """, "GL-038")
        assert not f.passed

    def test_fails_on_typed_variable_form(self) -> None:
        # GitLab's typed ``{value:, description:}`` variable form.
        f = run_check("""
        variables:
          CI_DEBUG_TRACE:
            value: "true"
            description: "verbose"
        build:
          script: [make]
        """, "GL-038")
        assert not f.passed

    def test_passes_when_explicitly_false(self) -> None:
        f = run_check("""
        variables:
          CI_DEBUG_TRACE: "false"
        build:
          script: [make]
        """, "GL-038")
        assert f.passed

    def test_passes_when_absent(self) -> None:
        f = run_check("""
        build:
          script: [make]
        """, "GL-038")
        assert f.passed
