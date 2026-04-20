"""Tests for the JUnit XML reporter."""
from __future__ import annotations

from xml.etree import ElementTree as ET

from pipeline_check.core.checks.base import Finding, Severity
from pipeline_check.core.junit_reporter import report_junit
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
    def test_valid_xml_round_trips(self):
        xml = report_junit([_f(), _f(check_id="IAM-001", passed=True)], _score())
        # Must parse cleanly.
        root = ET.fromstring(xml)
        assert root.tag == "testsuites"

    def test_root_counts_match(self):
        xml = report_junit(
            [_f(), _f(check_id="IAM-001", passed=True), _f(check_id="CB-001")],
            _score(),
        )
        root = ET.fromstring(xml)
        assert root.attrib["tests"] == "3"
        assert root.attrib["failures"] == "2"
        assert root.attrib["errors"] == "0"

    def test_suites_grouped_by_prefix(self):
        """The suite name is the check-ID prefix (letters before the first dash)."""
        xml = report_junit([
            _f(check_id="GHA-001"),
            _f(check_id="GHA-002"),
            _f(check_id="IAM-001"),
            _f(check_id="CB-005"),
        ], _score())
        root = ET.fromstring(xml)
        suite_names = sorted(s.attrib["name"] for s in root.findall("testsuite"))
        assert suite_names == ["CB", "GHA", "IAM"]

    def test_passing_testcase_has_no_failure(self):
        xml = report_junit([_f(passed=True)], _score())
        root = ET.fromstring(xml)
        tc = root.find("testsuite").find("testcase")
        assert tc.find("failure") is None

    def test_failing_testcase_has_failure_with_severity_type(self):
        xml = report_junit(
            [_f(severity=Severity.CRITICAL, description="Boom.")],
            _score(),
        )
        root = ET.fromstring(xml)
        fail = root.find("testsuite").find("testcase").find("failure")
        assert fail is not None
        assert fail.attrib["type"] == "CRITICAL"


class TestEscaping:
    def test_angle_brackets_in_description_dont_break_xml(self):
        xml = report_junit(
            [_f(description="Use <script>alert(1)</script> — dangerous!")],
            _score(),
        )
        # If escaping is broken this raises ParseError.
        root = ET.fromstring(xml)
        body = root.find("testsuite").find("testcase").find("failure").text or ""
        assert "<script>" in body  # round-tripped through ET
        # Raw XML must have it escaped.
        assert "&lt;script&gt;" in xml

    def test_ampersand_in_title_escaped(self):
        xml = report_junit([_f(title="Tom & Jerry")], _score())
        root = ET.fromstring(xml)
        tc = root.find("testsuite").find("testcase")
        assert tc.attrib["name"] == "Tom & Jerry"
        assert "Tom &amp; Jerry" in xml


class TestControlsPropagation:
    def test_controls_rendered_in_failure_body(self):
        finding = _f(controls=[
            ControlRef(
                standard="openssf_scorecard",
                standard_title="OpenSSF Scorecard",
                control_id="Dangerous-Workflow",
                control_title="No dangerous patterns",
            ),
            ControlRef(
                standard="soc2",
                standard_title="SOC 2 TSC",
                control_id="CC6.8",
                control_title="Malicious software controls",
            ),
        ])
        xml = report_junit([finding], _score())
        root = ET.fromstring(xml)
        body = root.find("testsuite").find("testcase").find("failure").text
        assert "openssf_scorecard:Dangerous-Workflow" in body
        assert "soc2:CC6.8" in body
