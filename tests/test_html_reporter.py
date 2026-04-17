"""Tests for the HTML reporter."""
from __future__ import annotations

import re

import pytest

from pipeline_check.core.checks.base import Finding, Severity
from pipeline_check.core.html_reporter import (
    _PROVIDER_PREFIXES,
    _provider_for,
    report_html,
)
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
    return {
        "grade": "C",
        "score": 60,
        "summary": {
            "CRITICAL": {"passed": 0, "failed": 1},
            "HIGH":     {"passed": 2, "failed": 1},
        },
    }


class TestProviderMap:
    """The filter dropdown is populated from _provider_for(); any
    prefix that falls through to 'other' becomes invisible in the UI.
    Guard against future rule families silently dropping out of the map.
    """

    # Every prefix we scan today — add here when a new rule family lands.
    # The assertion below enforces that the runtime map covers at least
    # this set, so adding a GCB-NNN / TF-NNN etc. doesn't bitrot the UI.
    _KNOWN_PREFIXES = {
        "GHA", "GL", "BB", "ADO", "JF", "CC", "GCB",
        "CB", "CP", "CD", "IAM", "S3", "ECR", "PBAC",
        "CT", "CWL", "CW", "EB", "SM", "SSM", "KMS",
        "CA", "CCM", "LMB", "SIGN",
        "TF", "CF", "CFN",
    }

    def test_every_known_prefix_maps_somewhere(self):
        missing = self._KNOWN_PREFIXES - set(_PROVIDER_PREFIXES)
        assert not missing, (
            f"Prefixes {missing} are not in _PROVIDER_PREFIXES — "
            "findings with those IDs will collapse to the 'other' "
            "bucket in the HTML filter and be unreachable."
        )

    @pytest.mark.parametrize("check_id,expected", [
        ("GCB-001",  "cloudbuild"),
        ("CFN-012",  "cloudformation"),
        ("CF-012",   "cloudformation"),
        ("SIGN-001", "aws"),
        ("LMB-003",  "aws"),
        ("CA-002",   "aws"),
        ("CCM-001",  "aws"),
        ("CWL-002",  "aws"),
        ("XYZ-999",  "other"),  # unknown still falls back
    ])
    def test_provider_for_mapping(self, check_id, expected):
        assert _provider_for(check_id) == expected


class TestSmoke:
    def test_returns_well_formed_html(self):
        html = report_html([_f()], _score())
        assert html.startswith("<!DOCTYPE html>")
        assert "<html" in html
        assert "</html>" in html
        assert "PipelineCheck" in html

    def test_all_findings_rendered_as_rows(self):
        findings = [
            _f(check_id="GHA-001"),
            _f(check_id="IAM-002", severity=Severity.CRITICAL),
            _f(check_id="CB-005", passed=True),
        ]
        html = report_html(findings, _score())
        # Each check_id appears at least once (in its own row).
        for f in findings:
            assert f.check_id in html

    def test_output_file_is_written(self, tmp_path):
        out = tmp_path / "report.html"
        report_html([_f()], _score(), output_path=str(out))
        assert out.exists()
        assert "<!DOCTYPE html>" in out.read_text(encoding="utf-8")


class TestDeepLinkAnchors:
    def test_each_row_has_a_stable_id(self):
        html = report_html([_f(check_id="GHA-001", resource=".github/workflows/ci.yml")], _score())
        # ID is ``finding-<lowercased check>-<slug>``.
        assert 'id="finding-gha-001-' in html

    def test_anchor_slug_escapes_path_characters(self):
        html = report_html([_f(check_id="S3-001", resource="s3://bucket/sub path")], _score())
        # Slashes, colons, and spaces collapse to dashes; the resulting
        # slug must be a valid URL fragment (no bare slashes or spaces).
        m = re.search(r'id="(finding-s3-001-[^"]*)"', html)
        assert m is not None
        slug = m.group(1)
        assert " " not in slug
        assert "/" not in slug

    def test_anchor_unique_across_rows_with_same_check(self):
        findings = [
            _f(check_id="GHA-001", resource="a.yml"),
            _f(check_id="GHA-001", resource="b.yml"),
        ]
        html = report_html(findings, _score())
        ids = re.findall(r'<tr id="(finding-[^"]*)"', html)
        assert len(ids) == 2
        assert len(set(ids)) == 2, f"Duplicate finding anchors: {ids}"


class TestInteractivity:
    """The interactive JS lives inline in the HTML. Assert the shape of
    that script so a refactor can't silently remove functionality.
    """

    def _html(self):
        return report_html([_f()], _score())

    def test_theme_honours_os_preference(self):
        html = self._html()
        assert "prefers-color-scheme: dark" in html
        assert "localStorage" in html
        assert "pipelinecheck.theme" in html

    def test_filter_state_syncs_to_url(self):
        html = self._html()
        # Hydrate + serialize round-trip.
        assert "URLSearchParams" in html
        assert "history.replaceState" in html

    def test_keyboard_shortcut_wired(self):
        html = self._html()
        # `/` focuses the filter; `Escape` clears it.
        assert "e.key === '/'" in html
        assert "e.key === 'Escape'" in html

    def test_expand_and_collapse_buttons_present(self):
        html = self._html()
        assert 'id="f-expand"' in html
        assert 'id="f-collapse"' in html

    def test_print_media_rules_present(self):
        html = self._html()
        assert "@media print" in html
        # Filter bar is hidden in print view.
        assert ".filter-bar" in html and "display: none" in html


class TestControlsPropagation:
    def test_kebab_case_control_ids_render(self):
        finding = _f(controls=[
            ControlRef(
                standard="openssf_scorecard",
                standard_title="OpenSSF Scorecard",
                control_id="Dangerous-Workflow",
                control_title="No dangerous patterns",
            ),
        ])
        html = report_html([finding], _score())
        assert "Dangerous-Workflow" in html
        # The standard slug drives the Standard filter dropdown.
        assert 'data-standards="openssf_scorecard"' in html
