"""JUnit XML structural-conformance tests.

JUnit has no single authoritative schema (the strict Ant/surefire XSD
rejects the de-facto format that Jenkins / GitLab / Azure DevOps
actually consume, see ``tests/schemas/README.md``), so this validates
the structural contract the format relies on using the standard library:
well-formed XML, the documented element tree, counts that agree with the
findings, and the absence of non-standard attributes.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

from pipeline_check.core.checks.base import Finding, Severity
from pipeline_check.core.junit_reporter import report_junit


def _f(check_id="CB-001", passed=False, severity=Severity.HIGH, **kw):
    return Finding(
        check_id=check_id,
        title=kw.get("title", "Plaintext secret"),
        severity=severity,
        resource=kw.get("resource", "proj"),
        description=kw.get("description", "A secret was found."),
        recommendation=kw.get("recommendation", "Use a secret store."),
        passed=passed,
    )


def _score(grade="C", score=70):
    return {"grade": grade, "score": score, "total": 0, "failed": 0, "passed": 0}


def _parse(findings, score=None):
    """Render + parse; ElementTree.fromstring raises on malformed XML."""
    return ET.fromstring(report_junit(findings, score or _score()))


def _all_elements(root):
    yield root
    for child in root:
        yield from _all_elements(child)


class TestJUnitStructure:
    def test_well_formed_and_root(self):
        root = _parse([_f()])
        assert root.tag == "testsuites"
        assert root.attrib["name"] == "pipeline_check"

    def test_empty_findings_well_formed(self):
        root = _parse([])
        assert root.tag == "testsuites"
        assert root.attrib["tests"] == "0"
        assert root.findall("testsuite") == []

    def test_root_counts_match_findings(self):
        findings = [
            _f("CB-001", passed=False),
            _f("CB-002", passed=True),
            _f("GHA-002", passed=False),
        ]
        root = _parse(findings)
        assert root.attrib["tests"] == "3"
        assert root.attrib["failures"] == "2"
        assert root.attrib["errors"] == "0"

    def test_suites_grouped_by_prefix(self):
        root = _parse([_f("CB-001"), _f("GHA-002"), _f("CB-003")])
        names = sorted(s.attrib["name"] for s in root.findall("testsuite"))
        assert names == ["CB", "GHA"]

    def test_failing_case_has_typed_failure(self):
        root = _parse([_f("IAM-001", passed=False, severity=Severity.CRITICAL)])
        case = root.find("testsuite/testcase")
        assert case.attrib["classname"] == "IAM-001"
        failure = case.find("failure")
        assert failure is not None
        assert failure.attrib["type"] == "CRITICAL"

    def test_passing_case_has_no_failure(self):
        root = _parse([_f("CB-001", passed=True)])
        case = root.find("testsuite/testcase")
        assert case.find("failure") is None


class TestJUnitProperties:
    """Run-level grade / score travel as standard ``<properties>``, not as
    non-standard ``data-*`` attributes that strict ingestors reject."""

    def test_grade_and_score_in_properties(self):
        root = _parse([_f("CB-001")], _score(grade="B", score=88))
        props = {
            p.attrib["name"]: p.attrib["value"]
            for p in root.findall("testsuite/properties/property")
        }
        assert props["pipeline-check.grade"] == "B"
        assert props["pipeline-check.score"] == "88"

    def test_properties_precede_testcases(self):
        # JUnit requires <properties> before the test cases in a suite.
        suite = _parse([_f("CB-001")]).find("testsuite")
        child_tags = [c.tag for c in suite]
        assert child_tags[0] == "properties"
        assert "testcase" in child_tags
        assert child_tags.index("properties") < child_tags.index("testcase")

    def test_no_data_star_attributes_anywhere(self):
        root = _parse([_f("CB-001", passed=False), _f("GHA-002", passed=True)])
        for el in _all_elements(root):
            for attr in el.attrib:
                assert not attr.startswith("data-"), (
                    f"non-standard {attr!r} on <{el.tag}>"
                )


class TestJUnitEscaping:
    def test_angle_brackets_dont_break_envelope(self):
        # A shell snippet in the description must not break the XML.
        f = _f("CB-001", passed=False, description="run <script> && curl x | sh")
        root = _parse([f])  # would raise ParseError if escaping were wrong
        body = root.find("testsuite/testcase/failure").text
        assert "<script>" in body

    def test_ampersand_in_title_escaped(self):
        f = _f("CB-001", passed=False, title="A & B < C")
        root = _parse([f])
        assert root.find("testsuite/testcase").attrib["name"] == "A & B < C"
