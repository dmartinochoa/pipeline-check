"""Tests for the Bitbucket Pipelines graph builder (DAG v2 increment 8).

The HTML renderer is covered generically in ``test_html_pipeline_dag.py``;
these exercise the Bitbucket-specific mapping: positional ordering becomes
``stage`` edges, ``parallel`` blocks run concurrently (no edge between
siblings), ``stage`` steps run sequentially, and every pipeline definition
in the file shares one graph (so a definition's chain is independent).
"""
from __future__ import annotations

from pipeline_check.core.checks.bitbucket._graph import build_graphs
from pipeline_check.core.checks.bitbucket.base import BitbucketContext
from pipeline_check.core.pipeline_graph_builders import build_graphs_for


def _graph(tmp_path, text):
    p = tmp_path / "bitbucket-pipelines.yml"
    p.write_text(text)
    return build_graphs(BitbucketContext.from_path(p))[0]


def _edges(graph):
    return {(e.src, e.dst, e.kind) for e in graph.edges}


def _jobs(graph):
    return {n.id for n in graph.nodes if n.kind == "job"}


def test_sequential_steps_chain_with_stage_edges(tmp_path):
    text = (
        "pipelines:\n"
        "  default:\n"
        "    - step: {name: build, script: [make]}\n"
        "    - step: {name: test, script: [pytest]}\n"
    )
    g = _graph(tmp_path, text)
    assert g.provider == "bitbucket"
    assert _jobs(g) == {"default[0]", "default[1]"}
    assert ("default[0]", "default[1]", "stage") in _edges(g)


def test_parallel_block_siblings_have_no_edge_between_them(tmp_path):
    text = (
        "pipelines:\n"
        "  default:\n"
        "    - step: {name: setup, script: [make]}\n"
        "    - parallel:\n"
        "        - step: {name: lint, script: [lint]}\n"
        "        - step: {name: test, script: [pytest]}\n"
    )
    g = _graph(tmp_path, text)
    e = _edges(g)
    lint, test = "default[1].parallel[0]", "default[1].parallel[1]"
    # The two parallel steps don't gate each other...
    assert (lint, test, "stage") not in e and (test, lint, "stage") not in e
    # ...but both run after the preceding step.
    assert ("default[0]", lint, "stage") in e
    assert ("default[0]", test, "stage") in e


def test_step_after_parallel_waits_for_every_parallel_sibling(tmp_path):
    text = (
        "pipelines:\n"
        "  default:\n"
        "    - parallel:\n"
        "        - step: {name: a, script: [a]}\n"
        "        - step: {name: b, script: [b]}\n"
        "    - step: {name: deploy, script: [deploy]}\n"
    )
    g = _graph(tmp_path, text)
    e = _edges(g)
    assert ("default[0].parallel[0]", "default[1]", "stage") in e
    assert ("default[0].parallel[1]", "default[1]", "stage") in e


def test_first_step_has_no_incoming_edge(tmp_path):
    text = "pipelines:\n  default:\n    - step: {name: a, script: [a]}\n"
    g = _graph(tmp_path, text)
    assert not any(dst == "default[0]" for _s, dst, _k in _edges(g))


def test_stage_inner_steps_run_sequentially(tmp_path):
    text = (
        "pipelines:\n"
        "  default:\n"
        "    - stage:\n"
        "        name: deploy\n"
        "        steps:\n"
        "          - step: {name: one, script: [a]}\n"
        "          - step: {name: two, script: [b]}\n"
    )
    g = _graph(tmp_path, text)
    assert ("default[0].stage[0]", "default[0].stage[1]", "stage") in _edges(g)


def test_definitions_share_one_graph_but_stay_independent(tmp_path):
    text = (
        "pipelines:\n"
        "  default:\n"
        "    - step: {name: d, script: [d]}\n"
        "  branches:\n"
        "    main:\n"
        "      - step: {name: m, script: [m]}\n"
        "  pull-requests:\n"
        "    '**':\n"
        "      - step: {name: p, script: [p]}\n"
    )
    graphs = build_graphs(
        BitbucketContext.from_path(_write(tmp_path, text)),
    )
    # One graph for the whole file (one file root).
    assert len(graphs) == 1
    g = graphs[0]
    assert _jobs(g) == {"default[0]", "branches.main[0]", "pull-requests.**[0]"}
    # No edges across definitions (they are alternative entry points).
    assert not _edges(g)


def _write(tmp_path, text):
    p = tmp_path / "bitbucket-pipelines.yml"
    p.write_text(text)
    return p


def test_registered_with_dispatcher(tmp_path):
    import sys

    from pipeline_check.core import pipeline_graph_builders as gb
    gb._BUILDERS.pop("bitbucket", None)
    sys.modules.pop("pipeline_check.core.checks.bitbucket._graph", None)

    p = _write(tmp_path, "pipelines:\n  default:\n    - step: {name: a, script: [a]}\n")
    graphs = build_graphs_for("bitbucket", BitbucketContext.from_path(p))
    assert len(graphs) == 1 and graphs[0].provider == "bitbucket"
