"""Tests for the Tekton pipeline-graph builder (DAG v2) and the
``job_anchors`` -> ``Location`` backfill that lets its findings overlay.

Tekton is multi-document (Task / Pipeline CRDs per ``---``), so these also
pin the per-document line bounding that keeps a finding in document B off
document A's graph. The Pipeline graph's edges come from ``runAfter`` and
from implicit ``$(tasks.X.results.Y)`` data dependencies; a Task graph
chains its steps sequentially.
"""
from __future__ import annotations

from pipeline_check.core.checks.base import Finding, Location, Severity
from pipeline_check.core.checks.tekton._graph import build_graphs
from pipeline_check.core.checks.tekton.base import TektonContext
from pipeline_check.core.checks.tekton.pipelines import TektonChecks
from pipeline_check.core.pipeline_graph import attach_findings
from pipeline_check.core.pipeline_graph_builders import build_graphs_for

_PIPELINE = """\
apiVersion: tekton.dev/v1
kind: Pipeline
metadata:
  name: build-and-deploy
spec:
  tasks:
    - name: fetch
      taskRef: {name: git-clone}
    - name: build
      runAfter: [fetch]
      taskRef: {name: kaniko}
    - name: deploy
      taskRef: {name: kubectl}
      params:
        - name: image
          value: "$(tasks.build.results.image-url)"
"""

_TASK = """\
apiVersion: tekton.dev/v1
kind: Task
metadata:
  name: git-clone
spec:
  steps:
    - name: clone
      image: alpine/git
      script: git clone "$(params.url)" .
    - name: checkout
      image: alpine/git
      script: git checkout "$(params.rev)"
"""

# A Task whose step both interpolates an untrusted param (TKN-003) and
# runs privileged (TKN-002), the per-step rules that attribute via anchors.
_OFFENDING_TASK = """\
apiVersion: tekton.dev/v1
kind: Task
metadata:
  name: risky
spec:
  steps:
    - name: run
      image: alpine@sha256:deadbeef
      securityContext:
        privileged: true
      script: echo "$(params.title)"
"""


def _graphs(tmp_path, text):
    p = tmp_path / "pipeline.yaml"
    p.write_text(text)
    return build_graphs(TektonContext.from_path(p))


def _edges(graph):
    return {(e.src, e.dst, e.kind) for e in graph.edges}


def _by_label(graphs, label):
    return next(
        g for g in graphs
        if next(n for n in g.nodes if n.kind == "file").label == label
    )


def test_pipeline_tasks_become_job_nodes(tmp_path):
    g = _graphs(tmp_path, _PIPELINE)[0]
    assert g.provider == "tekton"
    assert {n.id for n in g.nodes if n.kind == "job"} == {"fetch", "build", "deploy"}


def test_run_after_becomes_needs_edge(tmp_path):
    g = _graphs(tmp_path, _PIPELINE)[0]
    assert ("fetch", "build", "needs") in _edges(g)


def test_results_reference_becomes_implicit_needs_edge(tmp_path):
    g = _graphs(tmp_path, _PIPELINE)[0]
    # deploy references $(tasks.build.results.image-url) but has no runAfter.
    assert ("build", "deploy", "needs") in _edges(g)


def test_unlinked_task_has_no_incoming_edge(tmp_path):
    g = _graphs(tmp_path, _PIPELINE)[0]
    assert not any(dst == "fetch" for _src, dst, _k in _edges(g))


def test_task_steps_chain_sequentially(tmp_path):
    g = _graphs(tmp_path, _TASK)[0]
    assert {n.id for n in g.nodes if n.kind == "job"} == {"clone", "checkout"}
    assert ("clone", "checkout", "stage") in _edges(g)


def test_finally_task_is_a_node(tmp_path):
    text = (
        "apiVersion: tekton.dev/v1\nkind: Pipeline\nmetadata: {name: p}\n"
        "spec:\n  tasks:\n    - name: build\n      taskRef: {name: x}\n"
        "  finally:\n    - name: cleanup\n      taskRef: {name: y}\n"
    )
    g = _graphs(tmp_path, text)[0]
    assert "cleanup" in {n.id for n in g.nodes if n.kind == "job"}


def test_one_graph_per_document_with_bounded_roots(tmp_path):
    graphs = _graphs(tmp_path, _TASK + "---\n" + _PIPELINE)
    assert len(graphs) == 2
    ta = _by_label(graphs, "Task/git-clone")
    pl = _by_label(graphs, "Pipeline/build-and-deploy")
    root_a = next(n for n in ta.nodes if n.kind == "file")
    root_b = next(n for n in pl.nodes if n.kind == "file")
    assert root_a.start_line == 1 and root_a.end_line is not None
    assert root_b.start_line == root_a.end_line + 1
    assert root_b.end_line is None


def test_pipelinerun_document_carries_no_graph(tmp_path):
    text = (
        _TASK + "---\n"
        "apiVersion: tekton.dev/v1\nkind: PipelineRun\nmetadata: {name: r}\n"
        "spec:\n  pipelineRef: {name: build-and-deploy}\n"
    )
    graphs = _graphs(tmp_path, text)
    assert len(graphs) == 1
    assert next(n.label for n in graphs[0].nodes if n.kind == "file") == "Task/git-clone"


def test_registered_with_dispatcher(tmp_path):
    import sys

    from pipeline_check.core import pipeline_graph_builders as gb
    gb._BUILDERS.pop("tekton", None)
    sys.modules.pop("pipeline_check.core.checks.tekton._graph", None)

    p = tmp_path / "pipeline.yaml"
    p.write_text(_PIPELINE)
    graphs = build_graphs_for("tekton", TektonContext.from_path(p))
    assert len(graphs) == 1 and graphs[0].provider == "tekton"


# ── job_anchors -> Location backfill ───────────────────────────────────


def _run_checks(tmp_path, text):
    p = tmp_path / "pipeline.yaml"
    p.write_text(text)
    ctx = TektonContext.from_path(p)
    return TektonChecks(ctx).run(), str(p)


def test_anchor_backfill_gives_per_step_findings_a_location(tmp_path):
    findings, path = _run_checks(tmp_path, _OFFENDING_TASK)
    # TKN-002 (privileged) and TKN-003 (param injection) attribute via
    # job_anchors; the orchestrator backfills file/line locations.
    for cid in ("TKN-002", "TKN-003"):
        f = next(x for x in findings if x.check_id == cid and not x.passed)
        assert f.locations, f"{cid} should have a backfilled location"
        loc = f.locations[0]
        assert loc.path == path
        assert loc.start_line is not None


def test_backfilled_finding_overlays_onto_its_task_step(tmp_path):
    findings, path = _run_checks(tmp_path, _OFFENDING_TASK)
    graphs = build_graphs(TektonContext.from_path(tmp_path / "pipeline.yaml"))
    g = graphs[0]
    priv = next(x for x in findings if x.check_id == "TKN-002" and not x.passed)
    badges = attach_findings(g, [priv])
    # The privileged finding lands on the "run" step node, not just the root.
    assert "run" in badges


def test_native_location_finding_is_left_untouched(tmp_path):
    # TKN-001 sets its own locations; the backfill must not overwrite them.
    findings, path = _run_checks(tmp_path, _OFFENDING_TASK)
    f = next(x for x in findings if x.check_id == "TKN-001" and not x.passed)
    assert f.locations and all(loc.path == path for loc in f.locations)


def test_finding_in_second_document_not_attributed_to_first(tmp_path):
    graphs = _graphs(tmp_path, _TASK + "---\n" + _PIPELINE)
    ta = _by_label(graphs, "Task/git-clone")
    pl = _by_label(graphs, "Pipeline/build-and-deploy")
    build = next(n for n in pl.nodes if n.id == "build")
    finding = Finding(
        check_id="TKN-002", title="t", severity=Severity.HIGH,
        resource="tekton", description="", recommendation="", passed=False,
        locations=[Location(path=ta.path, start_line=build.start_line)],
    )
    assert attach_findings(ta, [finding]) == {}
    assert "build" in attach_findings(pl, [finding])
