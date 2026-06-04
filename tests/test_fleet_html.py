"""Tests for the fleet posture-graph HTML view (``fleet_html``)."""
from __future__ import annotations

from pipeline_check.core.chains.base import Chain
from pipeline_check.core.checks.base import Confidence, Severity
from pipeline_check.core.fleet import FleetDigest, FleetSnapshot
from pipeline_check.core.fleet_html import render_fleet_html


def _snap(
    coord: str, grade: str = "C", score: int = 70,
    failed: dict[str, int] | None = None, error: str = "",
) -> FleetSnapshot:
    return FleetSnapshot(
        coord=coord, grade=grade, score=score,
        failed_by_severity=failed or {}, total_failed=sum((failed or {}).values()),
        error=error,
    )


def _chain(
    source: str, target: str,
    chain_id: str = "CXPC-002", severity: Severity = Severity.CRITICAL,
) -> Chain:
    return Chain(
        chain_id=chain_id, title="x-repo chain",
        severity=severity, confidence=Confidence.MEDIUM,
        summary="", narrative="", mitre_attack=[], kill_chain_phase="",
        triggering_check_ids=[], triggering_findings=[],
        resources=["a.yml", "b.yml"], references=[], recommendation="",
        repos=[source, target],
    )


class TestFleetHtml:
    def test_renders_doctype_and_title(self) -> None:
        html = render_fleet_html(FleetDigest(snapshots=[_snap("o/a")]))
        assert html.startswith("<!DOCTYPE html>")
        assert "Pipeline-Check" in html and "Fleet Posture" in html

    def test_posture_cards_show_repo_grade_and_score(self) -> None:
        html = render_fleet_html(FleetDigest(snapshots=[
            _snap("o/prod", "D", 42, {"CRITICAL": 1, "HIGH": 3}),
        ]))
        assert "o/prod" in html
        assert "score 42" in html
        # grade chip uses the grade-D token
        assert "var(--grade-d)" in html

    def test_errored_snapshot_renders_error(self) -> None:
        html = render_fleet_html(FleetDigest(snapshots=[
            _snap("o/broken", error="clone failed: auth"),
        ]))
        assert "clone failed: auth" in html
        assert "errored" in html

    def test_graph_svg_has_nodes_and_edges(self) -> None:
        dg = FleetDigest(
            snapshots=[_snap("o/prod"), _snap("o/cons", "B", 85)],
            cxpc_chains=[_chain("o/prod", "o/cons")],
        )
        html = render_fleet_html(dg)
        assert "<svg" in html and "viewBox" in html
        # one arrowhead marker for the chain's severity, and a labeled edge
        assert "marker-end" in html
        assert "CXPC-002" in html
        # both endpoints render as node labels
        assert html.count('class="node-label"') == 2

    def test_unscanned_partner_is_dashed_muted_node(self) -> None:
        dg = FleetDigest(
            snapshots=[_snap("o/prod")],
            cxpc_chains=[_chain("o/prod", "o/external")],
        )
        html = render_fleet_html(dg)
        assert "o/external" in html
        # an unscanned node is drawn dashed and muted, and flagged in legend
        assert "stroke-dasharray" in html
        assert "not scanned" in html

    def test_bidirectional_edges_both_render(self) -> None:
        dg = FleetDigest(
            snapshots=[_snap("o/x"), _snap("o/y")],
            cxpc_chains=[
                _chain("o/x", "o/y", "CXPC-001", Severity.HIGH),
                _chain("o/y", "o/x", "CXPC-003", Severity.MEDIUM),
            ],
        )
        html = render_fleet_html(dg)
        assert "CXPC-001" in html and "CXPC-003" in html
        # two directed edges -> two <line> elements
        assert html.count("<line") == 2

    def test_no_edges_shows_note_not_svg(self) -> None:
        html = render_fleet_html(FleetDigest(snapshots=[_snap("o/a"), _snap("o/b")]))
        assert "No cross-repo attack chains detected" in html
        assert "<svg" not in html
        # posture cards still render
        assert "o/a" in html and "o/b" in html

    def test_empty_digest_does_not_crash(self) -> None:
        html = render_fleet_html(FleetDigest())
        assert "No repositories scanned" in html
        assert html.startswith("<!DOCTYPE html>")

    def test_self_contained_no_cdn_no_js(self) -> None:
        dg = FleetDigest(
            snapshots=[_snap("o/prod"), _snap("o/cons", "A", 95)],
            cxpc_chains=[_chain("o/prod", "o/cons")],
        )
        html = render_fleet_html(dg)
        # No remote resources (the only http is the SVG xmlns, not https),
        # and no script engine required.
        assert "https://" not in html
        assert "<script" not in html
        assert "cdn" not in html.lower()
        assert "<style>" in html  # styles are inlined

    def test_coord_is_html_escaped(self) -> None:
        # A coordinate with markup-significant chars must be escaped, not
        # injected raw into the node label / card.
        dg = FleetDigest(
            snapshots=[_snap("o/<img src=x>")],
            cxpc_chains=[_chain("o/<img src=x>", "o/safe")],
        )
        html = render_fleet_html(dg)
        assert "<img src=x>" not in html
        assert "&lt;img" in html
