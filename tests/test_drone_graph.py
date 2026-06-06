"""Tests for the Drone CI pipeline-graph builder (DAG v2 increment 5).

Drone is multi-document (one ``kind: pipeline`` per ``---``), so these
also pin the per-document line bounding that keeps a finding in document B
off document A's graph.
"""
from __future__ import annotations

from pipeline_check.core.checks.base import Finding, Location, Severity
from pipeline_check.core.checks.drone._graph import build_graphs
from pipeline_check.core.checks.drone.base import DroneContext
from pipeline_check.core.pipeline_graph import attach_findings
from pipeline_check.core.pipeline_graph_builders import build_graphs_for

_A = "kind: pipeline\nname: A\nsteps:\n  - {name: a1, image: x}\n  - {name: a2, image: x}\n"
_B = "kind: pipeline\nname: B\nsteps:\n  - {name: b1, image: x}\n"


def _graphs(tmp_path, text):
    p = tmp_path / ".drone.yml"
    p.write_text(text)
    return build_graphs(DroneContext.from_path(p))


def _edges(graph):
    return {(e.src, e.dst, e.kind) for e in graph.edges}


def test_one_graph_per_pipeline_document(tmp_path):
    graphs = _graphs(tmp_path, _A + "---\n" + _B)
    assert len(graphs) == 2
    labels = {next(n.label for n in g.nodes if n.kind == "file") for g in graphs}
    assert labels == {"A", "B"}
    assert all(g.provider == "drone" for g in graphs)


def test_steps_become_job_nodes(tmp_path):
    g = _graphs(tmp_path, _A)[0]
    assert {n.id for n in g.nodes if n.kind == "job"} == {"a1", "a2"}


def test_sequential_default_chains_steps(tmp_path):
    g = _graphs(tmp_path, _A)[0]
    assert ("a1", "a2", "stage") in _edges(g)


def test_depends_on_becomes_needs_and_disables_sequential(tmp_path):
    text = (
        "kind: pipeline\nname: A\nsteps:\n"
        "  - {name: build, image: x}\n"
        "  - {name: lint, image: x}\n"
        "  - {name: test, image: x, depends_on: [build]}\n"
    )
    g = _graphs(tmp_path, text)[0]
    assert ("build", "test", "needs") in _edges(g)
    # DAG mode (a depends_on exists): ``lint`` has none, so it starts
    # immediately with no incoming edge (no sequential chain).
    assert not any(dst == "lint" for _src, dst, _k in _edges(g))


def test_depends_on_unknown_step_dropped(tmp_path):
    text = "kind: pipeline\nname: A\nsteps:\n  - {name: a1, image: x, depends_on: [ghost]}\n"
    g = _graphs(tmp_path, text)[0]
    assert all(src != "ghost" for src, _dst, _k in _edges(g))


def test_document_roots_are_bounded(tmp_path):
    ga, gb = _graphs(tmp_path, _A + "---\n" + _B)
    root_a = next(n for n in ga.nodes if n.kind == "file")
    root_b = next(n for n in gb.nodes if n.kind == "file")
    # A's root stops before B begins; B's runs to EOF.
    assert root_a.start_line == 1 and root_a.end_line is not None
    assert root_b.start_line == root_a.end_line + 1
    assert root_b.end_line is None


def test_finding_in_second_document_not_attributed_to_first(tmp_path):
    ga, gb = _graphs(tmp_path, _A + "---\n" + _B)
    b1 = next(n for n in gb.nodes if n.id == "b1")
    finding = Finding(
        check_id="DR-014", title="t", severity=Severity.HIGH,
        resource=ga.path, description="", recommendation="", passed=False,
        locations=[Location(path=ga.path, start_line=b1.start_line)],
    )
    # The finding sits inside document B; it must overlay onto B's graph
    # only, never fall back to A's file root.
    assert attach_findings(ga, [finding]) == {}
    assert "b1" in attach_findings(gb, [finding])


def test_registered_with_dispatcher(tmp_path):
    p = tmp_path / ".drone.yml"
    p.write_text(_A)
    graphs = build_graphs_for("drone", DroneContext.from_path(p))
    assert len(graphs) == 1 and graphs[0].provider == "drone"
