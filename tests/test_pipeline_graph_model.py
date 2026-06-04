"""Tests for the pipeline-graph model + finding attachment."""
from __future__ import annotations

from pipeline_check.core.checks.base import Finding, Location, Severity
from pipeline_check.core.pipeline_graph import (
    GraphEdge,
    GraphNode,
    PipelineGraph,
    attach_findings,
)

_PATH = ".github/workflows/ci.yml"


def _graph() -> PipelineGraph:
    # root spans the whole file; one job with two steps with clean ranges.
    nodes = (
        GraphNode("__root__", "file", "ci.yml", _PATH, 1, None, None),
        GraphNode("build", "job", "build", _PATH, 5, 20, "__root__"),
        GraphNode("build#0", "step", "checkout", _PATH, 7, 9, "build"),
        GraphNode("build#1", "step", "deploy", _PATH, 10, 20, "build"),
    )
    edges = (GraphEdge("build#0", "build#1", "sequence"),)
    return PipelineGraph(_PATH, "github", nodes, edges, "__root__")


def _f(line: int | None = None, sev: Severity = Severity.HIGH,
       *, resource: str = _PATH, anchors: tuple[str, ...] = ()) -> Finding:
    locs = [Location(path=_PATH, start_line=line)] if line is not None else []
    return Finding(
        check_id="GHA-001", title="t", severity=sev, resource=resource,
        description="", recommendation="", passed=False,
        locations=locs, job_anchors=anchors,
    )


def test_finding_maps_to_deepest_step():
    badges = attach_findings(_graph(), [_f(8)])
    assert set(badges) == {"build#0"}
    assert badges["build#0"].count == 1


def test_finding_in_job_header_maps_to_job_not_step():
    # line 6 is inside the job (5-20) but before the first step (7-9).
    badges = attach_findings(_graph(), [_f(6)])
    assert set(badges) == {"build"}


def test_top_level_line_falls_back_to_root():
    # line 2 is above the job; no job/step contains it -> file root.
    badges = attach_findings(_graph(), [_f(2)])
    assert set(badges) == {"__root__"}


def test_lineless_finding_uses_job_anchor():
    badges = attach_findings(_graph(), [_f(None, anchors=("build",))])
    assert set(badges) == {"build"}


def test_lineless_finding_without_anchor_falls_back_to_root():
    badges = attach_findings(_graph(), [_f(None)])
    assert set(badges) == {"__root__"}


def test_finding_on_other_file_is_skipped():
    badges = attach_findings(_graph(), [_f(None, resource="other.yml")])
    assert badges == {}


def test_passed_findings_ignored():
    passed = Finding(
        check_id="X", title="t", severity=Severity.LOW, resource=_PATH,
        description="", recommendation="", passed=True,
        locations=[Location(path=_PATH, start_line=8)],
    )
    assert attach_findings(_graph(), [passed]) == {}


def test_worst_and_breakdown_accumulate():
    g = _graph()
    badges = attach_findings(g, [_f(8, Severity.HIGH), _f(8, Severity.CRITICAL)])
    b = badges["build#0"]
    assert b.count == 2
    assert b.worst is Severity.CRITICAL
    assert b.breakdown == {"HIGH": 1, "CRITICAL": 1}


def test_multi_location_finding_badges_each_node():
    f = Finding(
        check_id="AGG", title="t", severity=Severity.MEDIUM, resource=_PATH,
        description="", recommendation="", passed=False,
        locations=[
            Location(path=_PATH, start_line=8),   # build#0
            Location(path=_PATH, start_line=12),  # build#1
        ],
    )
    badges = attach_findings(_graph(), [f])
    assert set(badges) == {"build#0", "build#1"}
    assert badges["build#0"].count == 1 and badges["build#1"].count == 1
