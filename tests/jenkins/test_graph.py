"""Tests for the Jenkins pipeline-graph builder (DAG v2 increment 9).

Jenkinsfiles are Groovy, so the builder recovers stage ranges from the
same brace walk the provider uses and graphs the top-level stages, chained
sequentially. Nested stages (parallel branches, sub-stages) fold into
their enclosing top-level stage rather than becoming their own nodes.
"""
from __future__ import annotations

from pipeline_check.core.checks.base import Finding, Location, Severity
from pipeline_check.core.checks.jenkins._graph import build_graphs
from pipeline_check.core.checks.jenkins.base import JenkinsContext
from pipeline_check.core.pipeline_graph import attach_findings
from pipeline_check.core.pipeline_graph_builders import build_graphs_for

_DECLARATIVE = """\
pipeline {
  agent any
  stages {
    stage('Build') {
      steps { sh 'make' }
    }
    stage('Test') {
      steps { sh 'pytest' }
    }
    stage('Deploy') {
      steps { sh './deploy.sh' }
    }
  }
}
"""

_PARALLEL = """\
pipeline {
  stages {
    stage('Build') {
      steps { sh 'make' }
    }
    stage('Verify') {
      parallel {
        stage('Unit') { steps { sh 'pytest' } }
        stage('Lint') { steps { sh 'lint' } }
      }
    }
  }
}
"""


def _graphs(tmp_path, text):
    p = tmp_path / "Jenkinsfile"
    p.write_text(text)
    return build_graphs(JenkinsContext.from_path(p))


def _edges(graph):
    return {(e.src, e.dst, e.kind) for e in graph.edges}


def _jobs(graph):
    return {n.id for n in graph.nodes if n.kind == "job"}


def test_top_level_stages_become_job_nodes(tmp_path):
    g = _graphs(tmp_path, _DECLARATIVE)[0]
    assert g.provider == "jenkins"
    assert _jobs(g) == {"Build", "Test", "Deploy"}


def test_stages_chain_sequentially(tmp_path):
    g = _graphs(tmp_path, _DECLARATIVE)[0]
    e = _edges(g)
    assert ("Build", "Test", "stage") in e
    assert ("Test", "Deploy", "stage") in e


def test_first_stage_has_no_incoming_edge(tmp_path):
    g = _graphs(tmp_path, _DECLARATIVE)[0]
    assert not any(dst == "Build" for _s, dst, _k in _edges(g))


def test_parallel_branches_fold_into_enclosing_stage(tmp_path):
    g = _graphs(tmp_path, _PARALLEL)[0]
    # Unit / Lint are nested in Verify, so only Build + Verify are nodes.
    assert _jobs(g) == {"Build", "Verify"}
    assert ("Build", "Verify", "stage") in _edges(g)


def test_finding_inside_a_stage_overlays_onto_it(tmp_path):
    g = _graphs(tmp_path, _DECLARATIVE)[0]
    test_node = next(n for n in g.nodes if n.id == "Test")
    # The ``pytest`` line sits within the Test stage's span.
    line = test_node.start_line + 1
    finding = Finding(
        check_id="JF-001", title="t", severity=Severity.HIGH,
        resource=g.path, description="", recommendation="", passed=False,
        locations=[Location(path=g.path, start_line=line)],
    )
    badges = attach_findings(g, [finding])
    assert "Test" in badges and badges["Test"].worst is Severity.HIGH


def test_line_less_finding_falls_back_to_root(tmp_path):
    g = _graphs(tmp_path, _DECLARATIVE)[0]
    finding = Finding(
        check_id="JF-020", title="t", severity=Severity.MEDIUM,
        resource=g.path, description="", recommendation="", passed=False,
    )
    badges = attach_findings(g, [finding])
    assert g.root_id in badges


def test_scripted_pipeline_without_stages_has_no_job_nodes(tmp_path):
    text = "node {\n  sh 'make'\n  sh 'pytest'\n}\n"
    g = _graphs(tmp_path, text)[0]
    assert _jobs(g) == set()


def test_registered_with_dispatcher(tmp_path):
    import sys

    from pipeline_check.core import pipeline_graph_builders as gb
    gb._BUILDERS.pop("jenkins", None)
    sys.modules.pop("pipeline_check.core.checks.jenkins._graph", None)

    p = tmp_path / "Jenkinsfile"
    p.write_text(_DECLARATIVE)
    graphs = build_graphs_for("jenkins", JenkinsContext.from_path(p))
    assert len(graphs) == 1 and graphs[0].provider == "jenkins"
