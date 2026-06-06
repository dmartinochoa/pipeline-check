"""Tests for the Buildkite pipeline-graph builder (DAG v2 increment 6).

The HTML renderer is covered generically in ``test_html_pipeline_dag.py``;
these exercise the Buildkite-specific mapping: command steps become job
nodes, ``depends_on`` (by ``key``) becomes ``needs`` edges, and ``wait``
barriers become ``stage`` edges from every step in the previous wait-group.
"""
from __future__ import annotations

from pipeline_check.core.checks.base import Finding, Location, Severity
from pipeline_check.core.checks.buildkite._graph import build_graphs
from pipeline_check.core.checks.buildkite.base import BuildkiteContext
from pipeline_check.core.pipeline_graph import attach_findings
from pipeline_check.core.pipeline_graph_builders import build_graphs_for


def _graphs(tmp_path, text):
    p = tmp_path / "pipeline.yml"
    p.write_text(text)
    return build_graphs(BuildkiteContext.from_path(p))


def _edges(graph):
    return {(e.src, e.dst, e.kind) for e in graph.edges}


def test_command_steps_become_job_nodes(tmp_path):
    text = (
        "steps:\n"
        "  - {key: build, command: make}\n"
        "  - {key: test, command: pytest}\n"
    )
    g = _graphs(tmp_path, text)[0]
    assert g.provider == "buildkite"
    assert {n.id for n in g.nodes if n.kind == "job"} == {"build", "test"}


def test_keyless_step_falls_back_to_index_id(tmp_path):
    text = "steps:\n  - {command: make}\n  - {command: pytest}\n"
    g = _graphs(tmp_path, text)[0]
    assert {n.id for n in g.nodes if n.kind == "job"} == {"step0", "step1"}


def test_depends_on_becomes_needs_edge(tmp_path):
    text = (
        "steps:\n"
        "  - {key: build, command: make}\n"
        "  - {key: test, command: pytest, depends_on: [build]}\n"
    )
    g = _graphs(tmp_path, text)[0]
    assert ("build", "test", "needs") in _edges(g)


def test_depends_on_dict_form(tmp_path):
    text = (
        "steps:\n"
        "  - {key: build, command: make}\n"
        "  - key: test\n    command: pytest\n"
        "    depends_on:\n      - step: build\n        allow_failure: true\n"
    )
    g = _graphs(tmp_path, text)[0]
    assert ("build", "test", "needs") in _edges(g)


def test_depends_on_unknown_key_dropped(tmp_path):
    text = "steps:\n  - {key: test, command: pytest, depends_on: [ghost]}\n"
    g = _graphs(tmp_path, text)[0]
    assert all(src != "ghost" for src, _dst, _k in _edges(g))


def test_wait_barrier_chains_every_prev_step_to_every_next(tmp_path):
    text = (
        "steps:\n"
        "  - {key: a, command: a}\n"
        "  - {key: b, command: b}\n"
        "  - wait\n"
        "  - {key: c, command: c}\n"
        "  - {key: d, command: d}\n"
    )
    g = _graphs(tmp_path, text)
    e = _edges(g[0])
    # a, b are parallel (no edge between them); c, d each wait for both.
    assert ("a", "b", "stage") not in e and ("b", "a", "stage") not in e
    assert {("a", "c", "stage"), ("b", "c", "stage"),
            ("a", "d", "stage"), ("b", "d", "stage")} <= e


def test_steps_before_first_barrier_have_no_incoming_edge(tmp_path):
    text = (
        "steps:\n"
        "  - {key: a, command: a}\n"
        "  - {key: b, command: b}\n"
        "  - wait\n"
        "  - {key: c, command: c}\n"
    )
    g = _graphs(tmp_path, text)[0]
    assert not any(dst in ("a", "b") for _src, dst, _k in _edges(g))


def test_depends_on_step_skips_the_implicit_barrier_edge(tmp_path):
    text = (
        "steps:\n"
        "  - {key: a, command: a}\n"
        "  - wait\n"
        "  - {key: b, command: b, depends_on: [a]}\n"
        "  - {key: c, command: c}\n"
    )
    g = _graphs(tmp_path, text)[0]
    e = _edges(g)
    # b declares depends_on, so it gets only the needs edge, not a stage one.
    assert ("a", "b", "needs") in e
    assert ("a", "b", "stage") not in e
    # c has no depends_on, so it still gets the barrier stage edge.
    assert ("a", "c", "stage") in e


def test_block_step_acts_as_a_barrier(tmp_path):
    text = (
        "steps:\n"
        "  - {key: a, command: a}\n"
        "  - block: \"Deploy?\"\n"
        "  - {key: b, command: b}\n"
    )
    g = _graphs(tmp_path, text)[0]
    assert ("a", "b", "stage") in _edges(g)


def test_group_children_flatten_into_current_group(tmp_path):
    text = (
        "steps:\n"
        "  - group: \":hammer: build\"\n"
        "    steps:\n"
        "      - {key: a, command: a}\n"
        "      - {key: b, command: b}\n"
        "  - wait\n"
        "  - {key: c, command: c}\n"
    )
    g = _graphs(tmp_path, text)[0]
    job_ids = {n.id for n in g.nodes if n.kind == "job"}
    assert job_ids == {"a", "b", "c"}
    # The group's children are parallel siblings; both gate the next step.
    assert {("a", "c", "stage"), ("b", "c", "stage")} <= _edges(g)


def test_back_to_back_waits_bridge_as_one_barrier(tmp_path):
    text = (
        "steps:\n"
        "  - {key: a, command: a}\n"
        "  - wait\n"
        "  - wait\n"
        "  - {key: b, command: b}\n"
    )
    g = _graphs(tmp_path, text)[0]
    assert ("a", "b", "stage") in _edges(g)


def test_trigger_steps_are_skipped(tmp_path):
    text = (
        "steps:\n"
        "  - {key: a, command: a}\n"
        "  - trigger: deploy-pipeline\n"
    )
    g = _graphs(tmp_path, text)[0]
    assert {n.id for n in g.nodes if n.kind == "job"} == {"a"}


def test_finding_overlays_onto_containing_step(tmp_path):
    text = (
        "steps:\n"
        "  - {key: build, command: make}\n"
        "  - {key: test, command: pytest}\n"
    )
    g = _graphs(tmp_path, text)[0]
    test_node = next(n for n in g.nodes if n.id == "test")
    finding = Finding(
        check_id="BK-003", title="t", severity=Severity.HIGH,
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
    gb._BUILDERS.pop("buildkite", None)
    sys.modules.pop("pipeline_check.core.checks.buildkite._graph", None)

    p = tmp_path / "pipeline.yml"
    p.write_text("steps:\n  - {key: a, command: a}\n")
    graphs = build_graphs_for("buildkite", BuildkiteContext.from_path(p))
    assert len(graphs) == 1 and graphs[0].provider == "buildkite"
