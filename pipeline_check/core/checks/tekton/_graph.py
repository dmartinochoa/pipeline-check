"""Tekton step-level pipeline-graph builder (DAG v2).

A Tekton file is a multi-document stream of Kubernetes-style CRDs. Two
kinds carry a graph:

* ``Pipeline`` -> one graph whose nodes are the ``spec.tasks`` (and
  ``spec.finally``) entries. Edges come from two places: an explicit
  ``runAfter: [names]`` and an implicit data dependency, a task whose
  body references ``$(tasks.<other>.results.<r>)`` runs after ``<other>``.
  Both become ``needs`` edges. Tekton has no sequential default (a task
  with no predecessor starts immediately), so unlinked tasks carry no
  edge.
* ``Task`` / ``ClusterTask`` -> one graph whose nodes are the
  ``spec.steps``, which always run in declaration order, so each step
  chains off the previous one via a ``stage`` edge.

Because several documents share one file path, each graph's file-root is
bounded to its document's line range (reusing the Drone increment's
multi-doc fix), so a finding on document B doesn't fall back onto
document A's root. ``*Run`` documents carry no graph but still take part
in the boundary calculation so the bounds stay tight.

Findings reach these graphs because the per-step rules' ``job_anchors``
are resolved to ``Location``s in :mod:`pipeline_check.core.checks.tekton.pipelines`
(TKN-001 already carries them natively).
"""
from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

from ...pipeline_graph import GraphEdge, GraphNode, PipelineGraph
from ...pipeline_graph_builders import register_builder
from .._yaml_lines import line_of
from .base import TektonDoc, pipeline_tasks, step_name, task_steps

_ROOT_ID = "__root__"

# ``$(tasks.<name>.results.<output>)`` cross-task reference (the implicit
# ordering edge). Matches the producer-task name only.
_TASK_RESULT_RE = re.compile(
    r"\$\(tasks\.(?P<name>[A-Za-z_][A-Za-z0-9_-]*)\.results\.",
)


def _doc_label(doc: TektonDoc) -> str:
    if doc.name:
        return f"{doc.kind}/{doc.name}"
    return doc.kind or doc.path.rsplit("/", 1)[-1]


def _pipeline_finally(doc: TektonDoc) -> list[dict[str, Any]]:
    spec = doc.data.get("spec") or {}
    if not isinstance(spec, dict):
        return []
    fin = spec.get("finally") or []
    if not isinstance(fin, list):
        return []
    return [t for t in fin if isinstance(t, dict)]


def _task_id(task: dict[str, Any], idx: int, prefix: str) -> str:
    name = task.get("name")
    return name.strip() if isinstance(name, str) and name.strip() else f"{prefix}{idx}"


def _run_after(task: dict[str, Any]) -> list[str]:
    ra = task.get("runAfter")
    if isinstance(ra, str):
        return [ra]
    if isinstance(ra, list):
        return [r for r in ra if isinstance(r, str)]
    return []


def _walk_strings(obj: Any) -> Iterator[str]:
    """Yield every string leaf in a nested dict / list structure."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _walk_strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk_strings(v)


def _result_deps(task: dict[str, Any]) -> set[str]:
    """Producer-task names this task references via ``results``."""
    deps: set[str] = set()
    for s in _walk_strings(task):
        for m in _TASK_RESULT_RE.finditer(s):
            deps.add(m.group("name"))
    return deps


def _assign_ends(
    records: list[tuple[str, dict[str, Any]]], root_end: int | None,
) -> dict[str, int | None]:
    """End-of-span per record id: a node ends where the next (by source
    line) begins; the last node ends at the document boundary."""
    starts = {rid: line_of(d) for rid, d in records}
    ordered = sorted(
        records, key=lambda r: (starts[r[0]] is None, starts[r[0]] or 0),
    )
    ends: dict[str, int | None] = {}
    for i, (rid, _d) in enumerate(ordered):
        nxt = starts[ordered[i + 1][0]] if i + 1 < len(ordered) else None
        ends[rid] = (nxt - 1) if (nxt and starts[rid]) else root_end
    return ends


def _build_pipeline(
    doc: TektonDoc, *, root_start: int, root_end: int | None,
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
    for i, t in enumerate(pipeline_tasks(doc)):
        tid = _task_id(t, i, "task")
        if tid not in seen:
            seen.add(tid)
            records.append((tid, t))
    for i, t in enumerate(_pipeline_finally(doc)):
        tid = _task_id(t, i, "finally")
        if tid not in seen:
            seen.add(tid)
            records.append((tid, t))

    ends = _assign_ends(records, root_end)
    for tid, t in records:
        nodes.append(GraphNode(
            id=tid, kind="job", label=tid, path=path,
            start_line=line_of(t), end_line=ends[tid], parent=_ROOT_ID,
        ))

    seen_edges: set[tuple[str, str]] = set()
    for tid, t in records:
        for dep in set(_run_after(t)) | _result_deps(t):
            if dep in seen and dep != tid and (dep, tid) not in seen_edges:
                seen_edges.add((dep, tid))
                edges.append(GraphEdge(src=dep, dst=tid, kind="needs"))

    return PipelineGraph(
        path=path, provider="tekton",
        nodes=tuple(nodes), edges=tuple(edges), root_id=_ROOT_ID,
    )


def _build_task(
    doc: TektonDoc, *, root_start: int, root_end: int | None,
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
    for i, s in enumerate(task_steps(doc)):
        sid = step_name(s, i)
        if sid not in seen:
            seen.add(sid)
            records.append((sid, s))

    ends = _assign_ends(records, root_end)
    prev: str | None = None
    for sid, s in records:
        nodes.append(GraphNode(
            id=sid, kind="job", label=sid, path=path,
            start_line=line_of(s), end_line=ends[sid], parent=_ROOT_ID,
        ))
        if prev is not None:
            edges.append(GraphEdge(src=prev, dst=sid, kind="stage"))
        prev = sid

    return PipelineGraph(
        path=path, provider="tekton",
        nodes=tuple(nodes), edges=tuple(edges), root_id=_ROOT_ID,
    )


def build_graphs(context: Any) -> list[PipelineGraph]:
    """One graph per ``Pipeline`` / ``Task`` / ``ClusterTask`` document,
    each file-root bounded to its document's line range."""
    by_path: dict[str, list[TektonDoc]] = {}
    for doc in getattr(context, "docs", []):
        if isinstance(doc, TektonDoc):
            by_path.setdefault(doc.path, []).append(doc)

    out: list[PipelineGraph] = []
    for _path, docs in by_path.items():
        ranked = sorted(docs, key=lambda d: line_of(d.data) or 0)
        for i, doc in enumerate(ranked):
            start = line_of(doc.data) or 1
            nxt = line_of(ranked[i + 1].data) if i + 1 < len(ranked) else None
            end = (nxt - 1) if nxt else None
            # The first document covers from line 1 so leading content
            # isn't orphaned above its root.
            root_start = 1 if i == 0 else start
            if doc.kind == "Pipeline":
                out.append(_build_pipeline(
                    doc, root_start=root_start, root_end=end,
                ))
            elif doc.kind in ("Task", "ClusterTask"):
                out.append(_build_task(
                    doc, root_start=root_start, root_end=end,
                ))
    return out


register_builder("tekton", build_graphs)
