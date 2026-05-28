"""Tests for the GitLab Code Quality reporter."""
from __future__ import annotations

import json

from pipeline_check.core.checks.base import Finding, Location, Severity
from pipeline_check.core.codequality_reporter import (
    _SEVERITY_MAP,
    report_codequality,
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
        locations=kw.get("locations", []),
    )


class TestShape:
    def test_output_is_valid_json_array(self):
        text = report_codequality([_f(), _f(check_id="IAM-001")])
        parsed = json.loads(text)
        assert isinstance(parsed, list)
        assert len(parsed) == 2

    def test_each_issue_has_required_keys(self):
        text = report_codequality([_f()])
        issue = json.loads(text)[0]
        for key in ("description", "check_name", "fingerprint",
                    "severity", "location"):
            assert key in issue, f"missing {key}"
        assert "path" in issue["location"]

    def test_check_name_is_the_check_id(self):
        text = report_codequality([_f(check_id="TAINT-009")])
        assert json.loads(text)[0]["check_name"] == "TAINT-009"


class TestFilteringPassingFindings:
    def test_passing_findings_are_skipped(self):
        text = report_codequality([
            _f(check_id="A-1", passed=True),
            _f(check_id="A-2", passed=False),
        ])
        issues = json.loads(text)
        assert len(issues) == 1
        assert issues[0]["check_name"] == "A-2"

    def test_only_passing_findings_emits_empty_array(self):
        text = report_codequality([_f(passed=True)])
        assert json.loads(text) == []


class TestSeverityMapping:
    def test_critical_maps_to_blocker(self):
        text = report_codequality([_f(severity=Severity.CRITICAL)])
        assert json.loads(text)[0]["severity"] == "blocker"

    def test_high_maps_to_critical(self):
        text = report_codequality([_f(severity=Severity.HIGH)])
        assert json.loads(text)[0]["severity"] == "critical"

    def test_medium_maps_to_major(self):
        text = report_codequality([_f(severity=Severity.MEDIUM)])
        assert json.loads(text)[0]["severity"] == "major"

    def test_low_maps_to_minor(self):
        text = report_codequality([_f(severity=Severity.LOW)])
        assert json.loads(text)[0]["severity"] == "minor"

    def test_info_maps_to_info(self):
        text = report_codequality([_f(severity=Severity.INFO)])
        assert json.loads(text)[0]["severity"] == "info"


class TestLocationExplosion:
    def test_multiple_locations_become_multiple_issues(self):
        finding = _f(locations=[
            Location(path="ci.yml", start_line=5),
            Location(path="ci.yml", start_line=42),
            Location(path="other.yml", start_line=8),
        ])
        issues = json.loads(report_codequality([finding]))
        assert len(issues) == 3
        lines = sorted(i["location"]["lines"]["begin"] for i in issues)
        assert lines == [5, 8, 42]

    def test_no_locations_falls_back_to_resource_without_lines(self):
        finding = _f(resource="cfn/stack.yaml", locations=[])
        issue = json.loads(report_codequality([finding]))[0]
        assert issue["location"]["path"] == "cfn/stack.yaml"
        assert "lines" not in issue["location"]

    def test_empty_resource_falls_back_to_unknown_sentinel(self):
        finding = _f(resource="", locations=[])
        issue = json.loads(report_codequality([finding]))[0]
        assert issue["location"]["path"] == "unknown"

    def test_windows_path_is_normalized_to_forward_slashes(self):
        finding = _f(locations=[
            Location(path=".github\\workflows\\ci.yml", start_line=5),
        ])
        issue = json.loads(report_codequality([finding]))[0]
        assert issue["location"]["path"] == ".github/workflows/ci.yml"

    def test_windows_resource_fallback_is_normalized(self):
        finding = _f(resource="cfn\\stack.yaml", locations=[])
        issue = json.loads(report_codequality([finding]))[0]
        assert issue["location"]["path"] == "cfn/stack.yaml"

    def test_location_with_no_line_omits_lines_block(self):
        finding = _f(locations=[Location(path="ci.yml", start_line=None)])
        issue = json.loads(report_codequality([finding]))[0]
        assert issue["location"]["path"] == "ci.yml"
        assert "lines" not in issue["location"]


class TestFingerprint:
    def test_fingerprint_stable_across_runs(self):
        finding = _f(locations=[Location(path="ci.yml", start_line=5)])
        a = json.loads(report_codequality([finding]))[0]["fingerprint"]
        b = json.loads(report_codequality([finding]))[0]["fingerprint"]
        assert a == b

    def test_fingerprint_differs_by_line_number(self):
        f1 = _f(locations=[Location(path="ci.yml", start_line=5)])
        f2 = _f(locations=[Location(path="ci.yml", start_line=6)])
        a = json.loads(report_codequality([f1]))[0]["fingerprint"]
        b = json.loads(report_codequality([f2]))[0]["fingerprint"]
        assert a != b

    def test_fingerprint_differs_by_check_id(self):
        f1 = _f(check_id="A-1")
        f2 = _f(check_id="A-2")
        a = json.loads(report_codequality([f1]))[0]["fingerprint"]
        b = json.loads(report_codequality([f2]))[0]["fingerprint"]
        assert a != b

    def test_fingerprint_stable_when_description_changes(self):
        """Description prose drifts between releases (and one-off flags like
        ``--verify-secrets-show-identity`` append context). Fingerprint must
        stay constant so previously-dismissed MR threads don't churn."""
        f1 = _f(description="Action not pinned.")
        f2 = _f(description="Action is not pinned to a SHA.")
        a = json.loads(report_codequality([f1]))[0]["fingerprint"]
        b = json.loads(report_codequality([f2]))[0]["fingerprint"]
        assert a == b

    def test_fingerprint_stable_across_platforms(self):
        """Windows path with backslashes should yield the same fingerprint
        as the equivalent forward-slash path so a cross-OS scan dedupes."""
        win = _f(locations=[
            Location(path=".github\\workflows\\ci.yml", start_line=5),
        ])
        nix = _f(locations=[
            Location(path=".github/workflows/ci.yml", start_line=5),
        ])
        a = json.loads(report_codequality([win]))[0]["fingerprint"]
        b = json.loads(report_codequality([nix]))[0]["fingerprint"]
        assert a == b


class TestSeverityMapCoverage:
    def test_severity_map_covers_every_enum_member(self):
        """Adding a new ``Severity`` member without mapping it would silently
        downgrade real findings to ``info`` via the dict-get fallback. This
        test fails the moment the registries drift."""
        assert set(_SEVERITY_MAP) == set(Severity)
