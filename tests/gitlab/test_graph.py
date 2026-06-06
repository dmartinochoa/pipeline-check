"""Tests for the GitLab CI pipeline-graph builder (DAG v2 increment 2).

The HTML renderer is covered generically in ``test_html_pipeline_dag.py``;
these exercise the GitLab-specific mapping: which YAML becomes jobs, how
``needs:`` and stage ordering become edges, and that findings overlay onto
the job that contains them.
"""
from __future__ import annotations

from pipeline_check.core.checks.base import Finding, Location, Severity
from pipeline_check.core.checks.gitlab._graph import build_graphs
from pipeline_check.core.checks.gitlab.base import GitLabContext
from pipeline_check.core.pipeline_graph import attach_findings
from pipeline_check.core.pipeline_graph_builders import build_graphs_for


def _graph(tmp_path, yaml_text):
    p = tmp_path / ".gitlab-ci.yml"
    p.write_text(yaml_text)
    ctx = GitLabContext.from_path(p)
    graphs = build_graphs(ctx)
    return graphs[0]


def _edges(graph):
    return {(e.src, e.dst, e.kind) for e in graph.edges}


def test_jobs_become_nodes_reserved_keys_excluded(tmp_path):
    g = _graph(tmp_path, (
        "stages: [build, test]\n"
        "variables:\n  FOO: bar\n"
        "build-job:\n  stage: build\n  script: [make]\n"
        "test-job:\n  stage: test\n  script: [pytest]\n"
    ))
    assert g.provider == "gitlab"
    assert {n.id for n in g.nodes if n.kind == "job"} == {"build-job", "test-job"}
    assert sum(1 for n in g.nodes if n.kind == "file") == 1


def test_job_line_spans_are_contiguous(tmp_path):
    g = _graph(tmp_path, (
        "a:\n  script: [x]\n"
        "b:\n  script: [y]\n"
    ))
    spans = {n.id: (n.start_line, n.end_line) for n in g.nodes if n.kind == "job"}
    # First job ends where the second begins; the last extends to EOF.
    assert spans["a"][0] < spans["b"][0]
    assert spans["a"][1] == spans["b"][0] - 1
    assert spans["b"][1] is None


def test_explicit_needs_become_needs_edges(tmp_path):
    g = _graph(tmp_path, (
        "build:\n  stage: build\n  script: [x]\n"
        "deploy:\n  stage: deploy\n  needs: [build]\n  script: [x]\n"
    ))
    assert ("build", "deploy", "needs") in _edges(g)


def test_needs_dict_form_supported(tmp_path):
    g = _graph(tmp_path, (
        "build:\n  script: [x]\n"
        "deploy:\n  needs:\n    - job: build\n      artifacts: true\n  script: [x]\n"
    ))
    assert ("build", "deploy", "needs") in _edges(g)


def test_stage_ordering_edge_when_no_needs(tmp_path):
    g = _graph(tmp_path, (
        "stages: [build, test]\n"
        "b:\n  stage: build\n  script: [x]\n"
        "t:\n  stage: test\n  script: [x]\n"
    ))
    # ``t`` has no needs, so it waits for the prior stage's job ``b``.
    assert ("b", "t", "stage") in _edges(g)


def test_empty_needs_means_no_incoming_edges(tmp_path):
    g = _graph(tmp_path, (
        "stages: [build, test]\n"
        "b:\n  stage: build\n  script: [x]\n"
        "t:\n  stage: test\n  needs: []\n  script: [x]\n"
    ))
    # ``needs: []`` is "depend on nothing": no needs edge AND no stage edge.
    assert not any(dst == "t" for _src, dst, _kind in _edges(g))


def test_needs_to_unknown_job_dropped(tmp_path):
    g = _graph(tmp_path, (
        "deploy:\n  needs: [does-not-exist]\n  script: [x]\n"
    ))
    assert all(src != "does-not-exist" for src, _dst, _kind in _edges(g))


def test_finding_overlays_onto_containing_job(tmp_path):
    g = _graph(tmp_path, (
        "a:\n  script: [x]\n"
        "b:\n  script: [y]\n"
    ))
    b_node = next(n for n in g.nodes if n.id == "b")
    finding = Finding(
        check_id="GL-001", title="t", severity=Severity.HIGH,
        resource=g.path, description="", recommendation="", passed=False,
        locations=[Location(path=g.path, start_line=b_node.start_line)],
    )
    badges = attach_findings(g, [finding])
    assert "b" in badges and badges["b"].worst is Severity.HIGH


def test_registered_with_dispatcher(tmp_path):
    p = tmp_path / ".gitlab-ci.yml"
    p.write_text("build:\n  script: [x]\n")
    ctx = GitLabContext.from_path(p)
    graphs = build_graphs_for("gitlab", ctx)
    assert len(graphs) == 1 and graphs[0].provider == "gitlab"
