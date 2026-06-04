"""Tests for the step-level pipeline-DAG section of the HTML report."""
from __future__ import annotations

from pipeline_check.core.checks.base import Finding, Location, Severity
from pipeline_check.core.html_reporter import (
    _pipeline_dag_section_html,
    report_html,
)
from pipeline_check.core.pipeline_graph import GraphNode, PipelineGraph

_PATH = ".github/workflows/ci.yml"


def _graph(path: str = _PATH, job_label: str = "deploy") -> PipelineGraph:
    nodes = (
        GraphNode("__root__", "file", path.rsplit("/", 1)[-1], path, 1, None, None),
        GraphNode("deploy", "job", job_label, path, 5, None, "__root__"),
        GraphNode("deploy#0", "step", "run: terraform apply", path, 7, None, "deploy"),
    )
    return PipelineGraph(path, "github", nodes, (), "__root__")


def _crit(line: int = 7, path: str = _PATH) -> Finding:
    return Finding(
        check_id="GHA-117", title="t", severity=Severity.CRITICAL,
        resource=path, description="", recommendation="", passed=False,
        locations=[Location(path=path, start_line=line)],
    )


def _score():
    return {"grade": "C", "score": 60, "summary": {}}


def test_empty_when_no_graphs():
    assert _pipeline_dag_section_html([], [_crit()]) == ""


def test_renders_one_svg_per_graph():
    html = _pipeline_dag_section_html(
        [_graph("a.yml"), _graph("b.yml")], [_crit(path="a.yml")],
    )
    assert html.count("<svg") == 2
    assert html.count("<svg") == html.count("</svg>")  # balanced


def test_node_colored_by_worst_finding_severity():
    html = _pipeline_dag_section_html([_graph()], [_crit()])
    assert "#dc3545" in html  # CRITICAL color on the badged node


def test_finding_count_badge_rendered():
    # two criticals on the same step -> the job aggregate badge shows 2
    html = _pipeline_dag_section_html([_graph()], [_crit(), _crit()])
    assert ">2</text>" in html


def test_job_label_is_html_escaped():
    g = _graph(job_label="<script>alert(1)</script>")
    html = _pipeline_dag_section_html([g], [])
    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html


def test_section_is_self_contained():
    html = _pipeline_dag_section_html([_graph()], [_crit()])
    assert "https://" not in html
    assert "<script" not in html


def test_report_html_includes_section_with_graphs():
    html = report_html([_crit()], _score(), pipeline_graphs=[_graph()])
    assert "<h2>Pipeline graph</h2>" in html


def test_report_html_omits_section_without_graphs():
    # Backward compatible: the new param defaults to None -> no section.
    html = report_html([_crit()], _score())
    assert "<h2>Pipeline graph</h2>" not in html
