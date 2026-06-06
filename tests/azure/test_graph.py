"""Tests for the Azure DevOps pipeline-graph builder (DAG v2 increment 7).

The HTML renderer is covered generically in ``test_html_pipeline_dag.py``;
these exercise the Azure-specific mapping across the three shapes (flat
steps, flat jobs, staged jobs), job ``dependsOn`` -> ``needs`` edges, and
the stage-level sequencing (sequential default + explicit ``dependsOn``).
"""
from __future__ import annotations

from pipeline_check.core.checks.azure._graph import build_graphs
from pipeline_check.core.checks.azure.base import AzureContext
from pipeline_check.core.pipeline_graph_builders import build_graphs_for


def _graph(tmp_path, text):
    p = tmp_path / "azure-pipelines.yml"
    p.write_text(text)
    return build_graphs(AzureContext.from_path(p))[0]


def _edges(graph):
    return {(e.src, e.dst, e.kind) for e in graph.edges}


def _jobs(graph):
    return {n.id for n in graph.nodes if n.kind == "job"}


def test_flat_steps_become_one_job_with_step_children(tmp_path):
    text = (
        "steps:\n"
        "  - script: make build\n"
        "  - script: make test\n"
    )
    g = _graph(tmp_path, text)
    assert g.provider == "azure"
    assert _jobs(g) == {"<pipeline>"}
    steps = [n for n in g.nodes if n.kind == "step"]
    assert len(steps) == 2 and all(n.parent == "<pipeline>" for n in steps)
    assert ("<pipeline>#0", "<pipeline>#1", "sequence") in _edges(g)


def test_flat_jobs_depends_on_becomes_needs(tmp_path):
    text = (
        "jobs:\n"
        "  - job: Build\n    steps: [{script: make}]\n"
        "  - job: Test\n    dependsOn: Build\n    steps: [{script: pytest}]\n"
    )
    g = _graph(tmp_path, text)
    assert _jobs(g) == {"Build", "Test"}
    assert ("Build", "Test", "needs") in _edges(g)


def test_flat_jobs_without_depends_on_are_parallel(tmp_path):
    text = (
        "jobs:\n"
        "  - job: A\n    steps: [{script: a}]\n"
        "  - job: B\n    steps: [{script: b}]\n"
    )
    g = _graph(tmp_path, text)
    # No stages, no dependsOn: both jobs are independent, no edges between them.
    assert not any(k in ("needs", "stage") for _s, _d, k in _edges(g))


def test_staged_sequential_default_chains_stages(tmp_path):
    text = (
        "stages:\n"
        "  - stage: Build\n    jobs:\n      - job: b\n        steps: [{script: make}]\n"
        "  - stage: Deploy\n    jobs:\n      - job: d\n        steps: [{script: ./deploy}]\n"
    )
    g = _graph(tmp_path, text)
    assert _jobs(g) == {"Build.b", "Deploy.d"}
    # Deploy has no stage dependsOn, so it chains off Build (sequential default).
    assert ("Build.b", "Deploy.d", "stage") in _edges(g)


def test_stage_explicit_depends_on(tmp_path):
    text = (
        "stages:\n"
        "  - stage: A\n    jobs:\n      - job: a\n        steps: [{script: a}]\n"
        "  - stage: B\n    dependsOn: []\n    jobs:\n      - job: b\n        steps: [{script: b}]\n"
        "  - stage: C\n    dependsOn: [A]\n    jobs:\n      - job: c\n        steps: [{script: c}]\n"
    )
    g = _graph(tmp_path, text)
    e = _edges(g)
    # B opts out of any predecessor (dependsOn: []).
    assert not any(dst == "B.b" for _s, dst, _k in e)
    # C depends on A explicitly, not on the immediately-preceding B.
    assert ("A.a", "C.c", "stage") in e
    assert ("B.b", "C.c", "stage") not in e


def test_within_stage_job_depends_on(tmp_path):
    text = (
        "stages:\n"
        "  - stage: CI\n    jobs:\n"
        "      - job: compile\n        steps: [{script: make}]\n"
        "      - job: test\n        dependsOn: compile\n        steps: [{script: pytest}]\n"
    )
    g = _graph(tmp_path, text)
    assert ("CI.compile", "CI.test", "needs") in _edges(g)


def test_cross_stage_only_targets_entry_jobs(tmp_path):
    text = (
        "stages:\n"
        "  - stage: Build\n    jobs:\n      - job: b\n        steps: [{script: make}]\n"
        "  - stage: Test\n    jobs:\n"
        "      - job: unit\n        steps: [{script: u}]\n"
        "      - job: integ\n        dependsOn: unit\n        steps: [{script: i}]\n"
    )
    g = _graph(tmp_path, text)
    e = _edges(g)
    # ``unit`` is the entry job of Test, so Build chains into it...
    assert ("Build.b", "Test.unit", "stage") in e
    # ...but ``integ`` is gated behind ``unit`` within the stage, not by Build.
    assert ("Build.b", "Test.integ", "stage") not in e
    assert ("Test.unit", "Test.integ", "needs") in e


def test_deployment_job_strategy_steps_nest(tmp_path):
    text = (
        "jobs:\n"
        "  - deployment: Web\n"
        "    strategy:\n      runOnce:\n        deploy:\n"
        "          steps:\n            - script: ./deploy.sh\n"
    )
    g = _graph(tmp_path, text)
    assert "Web" in _jobs(g)
    steps = [n for n in g.nodes if n.kind == "step" and n.parent == "Web"]
    assert len(steps) == 1


def test_depends_on_unknown_job_dropped(tmp_path):
    text = (
        "jobs:\n"
        "  - job: only\n    dependsOn: ghost\n    steps: [{script: x}]\n"
    )
    g = _graph(tmp_path, text)
    assert all(src != "ghost" for src, _d, _k in _edges(g))


def test_registered_with_dispatcher(tmp_path):
    import sys

    from pipeline_check.core import pipeline_graph_builders as gb
    gb._BUILDERS.pop("azure", None)
    sys.modules.pop("pipeline_check.core.checks.azure._graph", None)

    p = tmp_path / "azure-pipelines.yml"
    p.write_text("steps:\n  - script: echo hi\n")
    graphs = build_graphs_for("azure", AzureContext.from_path(p))
    assert len(graphs) == 1 and graphs[0].provider == "azure"
