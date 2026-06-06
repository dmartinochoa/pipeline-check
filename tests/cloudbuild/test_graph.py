"""Tests for the Cloud Build pipeline-graph builder (DAG v2 increment 4).

The HTML renderer is covered generically in ``test_html_pipeline_dag.py``;
these exercise the Cloud Build mapping: each step is a node, ``waitFor``
becomes the DAG, and a step with no ``waitFor`` chains off the previous
one (the sequential default).
"""
from __future__ import annotations

from pipeline_check.core.checks.base import Finding, Location, Severity
from pipeline_check.core.checks.cloudbuild._graph import build_graphs
from pipeline_check.core.checks.cloudbuild.base import CloudBuildContext
from pipeline_check.core.pipeline_graph import attach_findings
from pipeline_check.core.pipeline_graph_builders import build_graphs_for


def _graph(tmp_path, steps_yaml: str):
    p = tmp_path / "cloudbuild.yaml"
    p.write_text(steps_yaml)
    return build_graphs(CloudBuildContext.from_path(p))[0]


def _edges(graph):
    return {(e.src, e.dst, e.kind) for e in graph.edges}


def test_steps_become_job_nodes(tmp_path):
    g = _graph(tmp_path, (
        "steps:\n"
        "  - id: build\n    name: gcr.io/cloud-builders/docker\n    args: ['x']\n"
        "  - id: test\n    name: gcr.io/cloud-builders/docker\n    args: ['y']\n"
    ))
    assert g.provider == "cloudbuild"
    # Steps render as boxes, so they are job-kind nodes.
    assert {n.id for n in g.nodes if n.kind == "job"} == {"build", "test"}
    assert sum(1 for n in g.nodes if n.kind == "file") == 1


def test_idless_step_labeled_by_image_basename(tmp_path):
    g = _graph(tmp_path, (
        "steps:\n  - name: gcr.io/cloud-builders/gcloud\n    args: ['x']\n"
    ))
    job = next(n for n in g.nodes if n.kind == "job")
    assert job.label == "gcloud"


def test_waitfor_becomes_needs_edge(tmp_path):
    g = _graph(tmp_path, (
        "steps:\n"
        "  - id: build\n    name: img\n    args: ['x']\n"
        "  - id: deploy\n    name: img\n    waitFor: ['build']\n    args: ['y']\n"
    ))
    assert ("build", "deploy", "needs") in _edges(g)


def test_waitfor_dash_starts_immediately(tmp_path):
    g = _graph(tmp_path, (
        "steps:\n"
        "  - id: a\n    name: img\n    args: ['x']\n"
        "  - id: b\n    name: img\n    waitFor: ['-']\n    args: ['y']\n"
    ))
    # ``b`` starts immediately: no incoming edge despite following ``a``.
    assert not any(dst == "b" for _src, dst, _k in _edges(g))


def test_no_waitfor_chains_off_previous(tmp_path):
    g = _graph(tmp_path, (
        "steps:\n"
        "  - id: a\n    name: img\n    args: ['x']\n"
        "  - id: b\n    name: img\n    args: ['y']\n"
    ))
    # ``b`` has no waitFor -> sequential default -> stage edge from ``a``.
    assert ("a", "b", "stage") in _edges(g)


def test_waitfor_unknown_id_dropped(tmp_path):
    g = _graph(tmp_path, (
        "steps:\n  - id: a\n    name: img\n    waitFor: ['ghost']\n    args: ['x']\n"
    ))
    assert all(src != "ghost" for src, _dst, _k in _edges(g))


def test_finding_overlays_onto_containing_step(tmp_path):
    g = _graph(tmp_path, (
        "steps:\n"
        "  - id: a\n    name: img\n    args: ['x']\n"
        "  - id: b\n    name: img\n    args: ['y']\n"
    ))
    b = next(n for n in g.nodes if n.id == "b")
    finding = Finding(
        check_id="GCB-001", title="t", severity=Severity.HIGH,
        resource=g.path, description="", recommendation="", passed=False,
        locations=[Location(path=g.path, start_line=b.start_line)],
    )
    badges = attach_findings(g, [finding])
    assert "b" in badges and badges["b"].worst is Severity.HIGH


def test_registered_with_dispatcher(tmp_path):
    p = tmp_path / "cloudbuild.yaml"
    p.write_text("steps:\n  - id: a\n    name: img\n    args: ['x']\n")
    graphs = build_graphs_for("cloudbuild", CloudBuildContext.from_path(p))
    assert len(graphs) == 1 and graphs[0].provider == "cloudbuild"
