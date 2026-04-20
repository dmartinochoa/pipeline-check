"""Tests for the Markdown reporter."""
from __future__ import annotations

from pipeline_check.core.checks.base import Finding, Severity
from pipeline_check.core.markdown_reporter import report_markdown
from pipeline_check.core.standards.base import ControlRef


def _f(check_id="GHA-001", passed=False, severity=Severity.HIGH, **kw):
    return Finding(
        check_id=check_id,
        title=kw.get("title", "Example finding"),
        severity=severity,
        resource=kw.get("resource", ".github/workflows/ci.yml"),
        description=kw.get("description", "Something is wrong."),
        recommendation=kw.get("recommendation", "Fix it."),
        passed=passed,
        controls=kw.get("controls", []),
        cwe=kw.get("cwe", []),
    )


def _score():
    return {"grade": "C", "score": 65, "summary": {}}


class TestShape:
    def test_has_h1_header(self):
        md = report_markdown([_f()], _score())
        assert md.splitlines()[0] == "# Pipeline Security Report"

    def test_summary_line_includes_grade_and_counts(self):
        findings = [
            _f(check_id="GHA-001", passed=False),
            _f(check_id="GHA-002", passed=False),
            _f(check_id="GHA-003", passed=False),
            _f(check_id="GHA-004", passed=True),
            _f(check_id="GHA-005", passed=True),
        ]
        md = report_markdown(findings, {"grade": "B", "score": 85, "summary": {}})
        assert "**Grade:**" in md
        assert " B " in md
        assert "**Score:** 85/100" in md
        assert "**Failed:** 3" in md
        assert "**Passed:** 2" in md

    def test_failures_section_renders_table(self):
        md = report_markdown([_f(severity=Severity.CRITICAL)], _score())
        assert "## Failures (1)" in md
        assert "| Severity | Check | Title | Resource | Controls |" in md
        assert "| 🔴 CRITICAL |" in md

    def test_passes_wrapped_in_collapsible_details(self):
        md = report_markdown([_f(passed=True)], _score())
        assert "<details>" in md
        assert "</details>" in md
        assert "Passing checks (1)" in md

    def test_no_failures_section_when_all_pass(self):
        md = report_markdown([_f(passed=True)], _score())
        assert "## No failures" in md
        assert "🎉" in md


class TestEscaping:
    def test_pipe_in_title_escaped(self):
        md = report_markdown([_f(title="foo | bar")], _score())
        assert "foo \\| bar" in md
        # The escaped pipe must not create a new column in the row.
        row_line = next(ln for ln in md.splitlines() if "foo" in ln)
        # Count unescaped pipes — should be 6 (row delimiters for 5 cols).
        unescaped = row_line.replace("\\|", "")
        assert unescaped.count("|") == 6

    def test_newline_in_title_collapsed(self):
        md = report_markdown([_f(title="multi\nline title")], _score())
        assert "multi\nline" not in md  # newline shouldn't survive into the row
        assert "multi line title" in md


class TestControlsPropagation:
    def test_controls_rendered_as_inline_tags(self):
        finding = _f(controls=[
            ControlRef(
                standard="openssf_scorecard",
                standard_title="OpenSSF Scorecard",
                control_id="Dangerous-Workflow",
                control_title="No dangerous patterns",
            ),
        ])
        md = report_markdown([finding], _score())
        assert "`openssf_scorecard:Dangerous-Workflow`" in md

    def test_many_controls_truncated_with_overflow_count(self):
        controls = [
            ControlRef(standard=f"std{i}", standard_title="x",
                       control_id=f"C{i}", control_title="t")
            for i in range(10)
        ]
        md = report_markdown([_f(controls=controls)], _score())
        # First six rendered, rest collapsed into "+4".
        assert "`std0:C0`" in md
        assert "`std5:C5`" in md
        assert "+4" in md
        assert "`std9:C9`" not in md
