"""Tests for the HTML report's blast-radius (resource heatmap) section.

Verifies:

  * the section is omitted entirely when no failing findings exist;
  * the SVG carries one ``<g>`` group per distinct failing resource;
  * tiles are sorted CRITICAL-first then by descending count;
  * tooltip text carries the full resource path and per-severity
    counts so a hover-only reader can triage without clicking
    through;
  * the section is plain inline SVG with no external CDN / JS
    dependency (the report has to stay a self-contained HTML
    file).
"""
from __future__ import annotations

import re

from pipeline_check.core.checks.base import (
    Confidence,
    Finding,
    Severity,
)
from pipeline_check.core.html_reporter import (
    _blast_radius_section_html,
)


def _f(check_id: str, resource: str, sev: Severity, *, passed: bool = False) -> Finding:
    return Finding(
        check_id=check_id, title="t", severity=sev,
        resource=resource, description="", recommendation="",
        passed=passed, confidence=Confidence.HIGH,
    )


class TestBlastRadius:
    def test_empty_when_no_failing_findings(self) -> None:
        # Passing findings never enter the heatmap.
        findings = [_f("X-1", "wf.yml", Severity.HIGH, passed=True)]
        assert _blast_radius_section_html(findings) == ""

    def test_empty_when_no_findings(self) -> None:
        assert _blast_radius_section_html([]) == ""

    def test_one_tile_per_resource(self) -> None:
        findings = [
            _f("X-1", "wf.yml", Severity.HIGH),
            _f("X-2", "wf.yml", Severity.MEDIUM),
            _f("X-3", "img.json", Severity.HIGH),
        ]
        out = _blast_radius_section_html(findings)
        # Two distinct resources -> two <g> tile groups.
        assert out.count("<g>") == 2
        assert "Blast radius (2 resources)" in out

    def test_tile_uses_worst_severity_color(self) -> None:
        findings = [
            _f("X-1", "wf.yml", Severity.MEDIUM),
            _f("X-2", "wf.yml", Severity.CRITICAL),
            _f("X-3", "wf.yml", Severity.LOW),
        ]
        out = _blast_radius_section_html(findings)
        # CRITICAL color: #dc3545
        assert "#dc3545" in out

    def test_tooltip_carries_severity_breakdown(self) -> None:
        findings = [
            _f("X-1", "wf.yml", Severity.CRITICAL),
            _f("X-2", "wf.yml", Severity.HIGH),
            _f("X-3", "wf.yml", Severity.HIGH),
        ]
        out = _blast_radius_section_html(findings)
        # The <title> child of the <g> is what browsers render as
        # the hover tooltip.
        assert "<title>wf.yml" in out
        assert "CRITICAL: 1" in out
        assert "HIGH: 2" in out

    def test_critical_tile_sorted_first(self) -> None:
        findings = [
            _f("X-1", "low.yml", Severity.LOW),
            _f("X-2", "crit.yml", Severity.CRITICAL),
            _f("X-3", "med.yml", Severity.MEDIUM),
        ]
        out = _blast_radius_section_html(findings)
        # CRITICAL tile's <title> appears before MEDIUM's in source
        # order; the SVG draws left-to-right top-to-bottom.
        crit = out.index("<title>crit.yml")
        med = out.index("<title>med.yml")
        low = out.index("<title>low.yml")
        assert crit < med < low

    def test_no_external_cdn_or_script(self) -> None:
        # The whole report has to stay a single offline HTML file.
        # The section should never reference an external URL or
        # inject a <script>.
        findings = [_f("X-1", "wf.yml", Severity.HIGH)]
        out = _blast_radius_section_html(findings)
        assert "http://" not in out
        assert "https://" not in out
        assert "<script" not in out
        # Inline SVG only.
        assert "<svg" in out

    def test_singular_finding_label(self) -> None:
        # "1 finding", not "1 findings".
        findings = [_f("X-1", "wf.yml", Severity.HIGH)]
        out = _blast_radius_section_html(findings)
        assert "1 finding<" in out
        assert "1 findings" not in out

    def test_label_truncated_for_long_resource(self) -> None:
        # Tile labels are clipped at 22 chars + ellipsis so the
        # 170px-wide tile doesn't overflow.
        long_resource = "a-very-long-resource-name-that-exceeds-the-limit.yml"
        findings = [_f("X-1", long_resource, Severity.HIGH)]
        out = _blast_radius_section_html(findings)
        # The tooltip carries the full path even when the rendered
        # label is truncated.
        assert long_resource in out
        # The visible label uses just the basename, then is clipped.
        assert "..." in out

    def test_does_not_crash_on_missing_resource(self) -> None:
        findings = [_f("X-1", "", Severity.HIGH)]
        out = _blast_radius_section_html(findings)
        # Empty resource gets the synthetic label.
        assert "(unknown)" in out


def test_section_renders_well_formed_svg() -> None:
    """The SVG element is balanced (open / close tag count match)."""
    findings = [
        _f("X-1", "a.yml", Severity.CRITICAL),
        _f("X-2", "b.yml", Severity.HIGH),
        _f("X-3", "c.yml", Severity.MEDIUM),
    ]
    out = _blast_radius_section_html(findings)
    open_g = len(re.findall(r"<g>", out))
    close_g = len(re.findall(r"</g>", out))
    assert open_g == close_g == 3
    assert out.count("<svg") == 1
    assert out.count("</svg>") == 1
