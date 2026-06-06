"""Tests for the Argo Workflows pipeline-graph builder (DAG v2) and the
``job_anchors`` -> ``Location`` backfill that lets its findings overlay.

Argo is multi-document. Each template-bearing document becomes one graph
whose nodes are its templates; ``dag.tasks[].template`` /
``steps[][].template`` invocations become ``needs`` edges (caller ->
callee). The orchestrator backfills the per-template rules' anchors into
locations so those findings carry a file/line and overlay onto the graph.
"""
from __future__ import annotations

from pipeline_check.core.checks.argo._graph import build_graphs
from pipeline_check.core.checks.argo.base import ArgoContext
from pipeline_check.core.checks.argo.pipelines import _backfill_anchor_locations
from pipeline_check.core.checks.base import Finding, Location, Severity
from pipeline_check.core.pipeline_graph import attach_findings
from pipeline_check.core.pipeline_graph_builders import build_graphs_for

_DAG = """\
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  name: ci
spec:
  entrypoint: main
  templates:
    - name: main
      dag:
        tasks:
          - name: a
            template: build
          - name: b
            template: test
            dependencies: [a]
    - name: build
      container:
        image: golang:1.22
    - name: test
      container:
        image: golang:1.22
"""

_STEPS = """\
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  name: seq
spec:
  entrypoint: main
  templates:
    - name: main
      steps:
        - - name: one
            template: build
        - - name: two
            template: deploy
    - name: build
      container: {image: alpine}
    - name: deploy
      container: {image: alpine}
"""


def _graphs(tmp_path, text):
    p = tmp_path / "wf.yaml"
    p.write_text(text)
    return build_graphs(ArgoContext.from_path(p))


def _edges(graph):
    return {(e.src, e.dst, e.kind) for e in graph.edges}


def _jobs(graph):
    return {n.id for n in graph.nodes if n.kind == "job"}


def test_templates_become_job_nodes(tmp_path):
    g = _graphs(tmp_path, _DAG)[0]
    assert g.provider == "argo"
    assert _jobs(g) == {"main", "build", "test"}


def test_dag_task_template_refs_become_needs_edges(tmp_path):
    g = _graphs(tmp_path, _DAG)[0]
    e = _edges(g)
    # main invokes build and test (caller -> callee).
    assert ("main", "build", "needs") in e
    assert ("main", "test", "needs") in e


def test_leaf_templates_have_no_outgoing_edge(tmp_path):
    g = _graphs(tmp_path, _DAG)[0]
    assert not any(src in ("build", "test") for src, _d, _k in _edges(g))


def test_steps_template_refs_become_needs_edges(tmp_path):
    g = _graphs(tmp_path, _STEPS)[0]
    e = _edges(g)
    assert ("main", "build", "needs") in e
    assert ("main", "deploy", "needs") in e


def test_unknown_template_ref_dropped(tmp_path):
    text = (
        "apiVersion: argoproj.io/v1alpha1\nkind: Workflow\nmetadata: {name: w}\n"
        "spec:\n  templates:\n"
        "    - name: main\n      dag:\n        tasks:\n"
        "          - name: a\n            template: ghost\n"
    )
    g = _graphs(tmp_path, text)[0]
    assert all(dst != "ghost" for _s, dst, _k in _edges(g))


def test_one_graph_per_document_with_bounded_roots(tmp_path):
    graphs = _graphs(tmp_path, _DAG + "---\n" + _STEPS)
    assert len(graphs) == 2
    roots = sorted(
        (next(n for n in g.nodes if n.kind == "file") for g in graphs),
        key=lambda n: n.start_line,
    )
    assert roots[0].start_line == 1 and roots[0].end_line is not None
    assert roots[1].start_line == roots[0].end_line + 1
    assert roots[1].end_line is None


def test_registered_with_dispatcher(tmp_path):
    import sys

    from pipeline_check.core import pipeline_graph_builders as gb
    gb._BUILDERS.pop("argo", None)
    sys.modules.pop("pipeline_check.core.checks.argo._graph", None)

    p = tmp_path / "wf.yaml"
    p.write_text(_DAG)
    graphs = build_graphs_for("argo", ArgoContext.from_path(p))
    assert len(graphs) == 1 and graphs[0].provider == "argo"


# ── job_anchors -> Location backfill ───────────────────────────────────


def _ctx(tmp_path, text):
    p = tmp_path / "wf.yaml"
    p.write_text(text)
    return ArgoContext.from_path(p), str(p)


def test_anchor_backfill_resolves_template_to_a_location(tmp_path):
    ctx, path = _ctx(tmp_path, _DAG)
    doc_index = {(d.kind, d.name): d for d in ctx.docs}
    f = Finding(
        check_id="ARGO-005", title="t", severity=Severity.HIGH,
        resource="argo", description="", recommendation="", passed=False,
        job_anchors=("Workflow/ci:build",),
    )
    _backfill_anchor_locations(f, doc_index)
    assert f.locations and f.locations[0].path == path
    assert f.locations[0].start_line is not None


def test_backfilled_finding_overlays_onto_its_template(tmp_path):
    ctx, path = _ctx(tmp_path, _DAG)
    doc_index = {(d.kind, d.name): d for d in ctx.docs}
    g = build_graphs(ctx)[0]
    f = Finding(
        check_id="ARGO-005", title="t", severity=Severity.HIGH,
        resource="argo", description="", recommendation="", passed=False,
        job_anchors=("Workflow/ci:build",),
    )
    _backfill_anchor_locations(f, doc_index)
    assert "build" in attach_findings(g, [f])


def test_backfill_leaves_existing_locations_untouched(tmp_path):
    ctx, path = _ctx(tmp_path, _DAG)
    doc_index = {(d.kind, d.name): d for d in ctx.docs}
    native = Location(path=path, start_line=3, end_line=3)
    f = Finding(
        check_id="ARGO-002", title="t", severity=Severity.HIGH,
        resource="argo", description="", recommendation="", passed=False,
        locations=[native], job_anchors=("Workflow/ci:build",),
    )
    _backfill_anchor_locations(f, doc_index)
    assert f.locations == [native]


def test_backfill_noop_without_anchors(tmp_path):
    ctx, _path = _ctx(tmp_path, _DAG)
    doc_index = {(d.kind, d.name): d for d in ctx.docs}
    f = Finding(
        check_id="ARGO-009", title="t", severity=Severity.LOW,
        resource="argo", description="", recommendation="", passed=False,
    )
    _backfill_anchor_locations(f, doc_index)
    assert f.locations == []
