"""Tests for the CircleCI pipeline-graph builder (DAG v2 increment 3).

The HTML renderer is covered generically in ``test_html_pipeline_dag.py``;
these exercise the CircleCI-specific mapping: jobs under ``jobs:`` become
nodes, steps nest under them, and the ``workflows.<name>.jobs[].requires``
references become edges (unioned across workflows).
"""
from __future__ import annotations

from pipeline_check.core.checks.base import Finding, Location, Severity
from pipeline_check.core.checks.circleci._graph import build_graphs
from pipeline_check.core.checks.circleci.base import CircleCIContext
from pipeline_check.core.pipeline_graph import attach_findings
from pipeline_check.core.pipeline_graph_builders import build_graphs_for

_JOBS = (
    "jobs:\n"
    "  build:\n    steps:\n      - checkout\n      - run: make\n"
    "  test:\n    steps:\n      - run: {name: unit, command: pytest}\n"
    "  deploy:\n    steps:\n      - run: ./deploy.sh\n"
)


def _graph(tmp_path, workflows: str):
    p = tmp_path / "config.yml"
    p.write_text("version: 2.1\n" + _JOBS + workflows)
    return build_graphs(CircleCIContext.from_path(p))[0]


def _edges(graph):
    return {(e.src, e.dst, e.kind) for e in graph.edges}


def test_jobs_and_steps_become_nodes(tmp_path):
    g = _graph(tmp_path, "workflows:\n  ci:\n    jobs:\n      - build\n")
    assert g.provider == "circleci"
    assert {n.id for n in g.nodes if n.kind == "job"} == {"build", "test", "deploy"}
    assert sum(1 for n in g.nodes if n.kind == "file") == 1
    # build has a bare ``checkout`` step and a ``run`` step.
    build_steps = [n.label for n in g.nodes if n.kind == "step" and n.parent == "build"]
    assert build_steps == ["checkout", "run: make"]


def test_step_run_dict_label_prefers_name(tmp_path):
    g = _graph(tmp_path, "workflows:\n  ci:\n    jobs:\n      - test\n")
    test_steps = [n.label for n in g.nodes if n.parent == "test" and n.kind == "step"]
    assert test_steps == ["run: unit"]


def test_requires_becomes_needs_edge(tmp_path):
    g = _graph(tmp_path, (
        "workflows:\n  ci:\n    jobs:\n"
        "      - build\n"
        "      - test:\n          requires: [build]\n"
    ))
    assert ("build", "test", "needs") in _edges(g)


def test_requires_unioned_across_workflows(tmp_path):
    # ``deploy`` requires ``test`` in one workflow and ``build`` in another;
    # both edges show up on the single per-file graph.
    g = _graph(tmp_path, (
        "workflows:\n"
        "  ci:\n    jobs:\n"
        "      - test\n"
        "      - deploy:\n          requires: [test]\n"
        "  nightly:\n    jobs:\n"
        "      - build\n"
        "      - deploy:\n          requires: [build]\n"
    ))
    assert ("test", "deploy", "needs") in _edges(g)
    assert ("build", "deploy", "needs") in _edges(g)


def test_requires_to_unknown_job_dropped(tmp_path):
    # A requires on a name that isn't a ``jobs:`` entry (an orb job or an
    # alias) is not turned into an edge.
    g = _graph(tmp_path, (
        "workflows:\n  ci:\n    jobs:\n"
        "      - deploy:\n          requires: [some-orb/publish]\n"
    ))
    assert all(src != "some-orb/publish" for src, _dst, _k in _edges(g))


def test_step_sequence_edges(tmp_path):
    g = _graph(tmp_path, "workflows:\n  ci:\n    jobs:\n      - build\n")
    assert ("build#0", "build#1", "sequence") in _edges(g)


def test_finding_overlays_onto_containing_job(tmp_path):
    g = _graph(tmp_path, "workflows:\n  ci:\n    jobs:\n      - build\n")
    test_node = next(n for n in g.nodes if n.id == "test")
    finding = Finding(
        check_id="CC-001", title="t", severity=Severity.HIGH,
        resource=g.path, description="", recommendation="", passed=False,
        locations=[Location(path=g.path, start_line=test_node.start_line)],
    )
    badges = attach_findings(g, [finding])
    assert "test" in badges and badges["test"].worst is Severity.HIGH


def test_registered_with_dispatcher(tmp_path):
    # Drop the eager registration so build_graphs_for exercises the lazy
    # import + registration path, not the one this module already triggered.
    import sys

    from pipeline_check.core import pipeline_graph_builders as gb
    gb._BUILDERS.pop("circleci", None)
    sys.modules.pop("pipeline_check.core.checks.circleci._graph", None)

    p = tmp_path / "config.yml"
    p.write_text("version: 2.1\n" + _JOBS + "workflows:\n  ci:\n    jobs:\n      - build\n")
    graphs = build_graphs_for("circleci", CircleCIContext.from_path(p))
    assert len(graphs) == 1 and graphs[0].provider == "circleci"
