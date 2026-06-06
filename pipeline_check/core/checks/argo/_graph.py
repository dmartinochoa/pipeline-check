"""Argo Workflows step-level pipeline-graph builder (DAG v2).

An Argo file is a multi-document stream of CRDs. Each template-bearing
document (``Workflow`` / ``WorkflowTemplate`` / ``ClusterWorkflowTemplate``
/ ``CronWorkflow``) becomes one graph whose nodes are its ``spec.templates``
(the unit findings anchor on, ``<Kind>/<name>:<template>``). Edges are
template invocations: a ``dag`` template's ``tasks[].template`` and a
``steps`` template's ``steps[][].template`` references become ``needs``
edges from the calling template to the called one, so the entrypoint sits
upstream of the workers it fans out to.

Because several documents share one file path, each graph's file-root is
bounded to its document's line range (reusing the Drone increment's
multi-doc fix). ``templateRef`` (cross-workflow) references have no inline
body here and are dropped from the edge set rather than guessed at.

Findings reach these graphs because the per-template rules' ``job_anchors``
are resolved to ``Location``s in :mod:`pipeline_check.core.checks.argo.pipelines`
(ARGO-001 / ARGO-002 already carry them natively).
"""
from __future__ import annotations

from typing import Any

from ...pipeline_graph import GraphEdge, GraphNode, PipelineGraph
from ...pipeline_graph_builders import register_builder
from .._yaml_lines import line_of
from .base import ArgoDoc, iter_templates, template_name

_ROOT_ID = "__root__"


def _doc_label(doc: ArgoDoc) -> str:
    if doc.name:
        return f"{doc.kind}/{doc.name}"
    return doc.kind or doc.path.rsplit("/", 1)[-1]


def _referenced_templates(template: dict[str, Any]) -> set[str]:
    """Template names this template invokes via its ``dag`` / ``steps``."""
    refs: set[str] = set()
    dag = template.get("dag")
    if isinstance(dag, dict):
        tasks = dag.get("tasks")
        if isinstance(tasks, list):
            for task in tasks:
                if isinstance(task, dict):
                    ref = task.get("template")
                    if isinstance(ref, str) and ref.strip():
                        refs.add(ref.strip())
    steps = template.get("steps")
    if isinstance(steps, list):
        for group in steps:
            # Each entry is a list of parallel steps, or (loosely) a step.
            members = group if isinstance(group, list) else [group]
            for step in members:
                if isinstance(step, dict):
                    ref = step.get("template")
                    if isinstance(ref, str) and ref.strip():
                        refs.add(ref.strip())
    return refs


def _build_one(
    doc: ArgoDoc, *, root_start: int, root_end: int | None,
) -> PipelineGraph:
    path = doc.path
    nodes: list[GraphNode] = [
        GraphNode(
            id=_ROOT_ID, kind="file", label=_doc_label(doc), path=path,
            start_line=root_start, end_line=root_end, parent=None,
        ),
    ]
    edges: list[GraphEdge] = []

    records: list[tuple[str, dict[str, Any]]] = []
    seen: set[str] = set()
    for idx, tmpl in enumerate(iter_templates(doc)):
        tid = template_name(tmpl, idx)
        if tid not in seen:
            seen.add(tid)
            records.append((tid, tmpl))

    starts = {tid: line_of(t) for tid, t in records}
    ordered = sorted(records, key=lambda r: (starts[r[0]] is None, starts[r[0]] or 0))
    ends: dict[str, int | None] = {}
    for i, (tid, _t) in enumerate(ordered):
        nxt = starts[ordered[i + 1][0]] if i + 1 < len(ordered) else None
        ends[tid] = (nxt - 1) if (nxt and starts[tid]) else root_end

    for tid, t in records:
        nodes.append(GraphNode(
            id=tid, kind="job", label=tid, path=path,
            start_line=starts[tid], end_line=ends[tid], parent=_ROOT_ID,
        ))

    seen_edges: set[tuple[str, str]] = set()
    for tid, t in records:
        for ref in _referenced_templates(t):
            if ref in seen and ref != tid and (tid, ref) not in seen_edges:
                seen_edges.add((tid, ref))
                edges.append(GraphEdge(src=tid, dst=ref, kind="needs"))

    return PipelineGraph(
        path=path, provider="argo",
        nodes=tuple(nodes), edges=tuple(edges), root_id=_ROOT_ID,
    )


def build_graphs(context: Any) -> list[PipelineGraph]:
    """One graph per template-bearing Argo document, each file-root bounded
    to its document's line range."""
    by_path: dict[str, list[ArgoDoc]] = {}
    for doc in getattr(context, "docs", []):
        if isinstance(doc, ArgoDoc):
            by_path.setdefault(doc.path, []).append(doc)

    out: list[PipelineGraph] = []
    for _path, docs in by_path.items():
        ranked = sorted(docs, key=lambda d: line_of(d.data) or 0)
        for i, doc in enumerate(ranked):
            start = line_of(doc.data) or 1
            nxt = line_of(ranked[i + 1].data) if i + 1 < len(ranked) else None
            end = (nxt - 1) if nxt else None
            root_start = 1 if i == 0 else start
            if any(True for _ in iter_templates(doc)):
                out.append(_build_one(
                    doc, root_start=root_start, root_end=end,
                ))
    return out


register_builder("argo", build_graphs)
