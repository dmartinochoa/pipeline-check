"""Drone CI step-level pipeline-graph builder (DAG v2).

A ``.drone.yml`` is a multi-document stream, one ``kind: pipeline`` per
``---``. Each pipeline is a flat list of steps that run sequentially by
default; any ``depends_on`` switches the whole pipeline into DAG mode
(steps without ``depends_on`` then start immediately). Each step is the
unit of work, so it maps to a ``job`` node (the renderer lays jobs out as
boxes). Edges: ``depends_on`` -> ``needs``; in sequential mode each step
chains off the previous one via a ``stage`` edge.

Because several pipelines share one file path, the file-root node of each
graph is bounded to that document's line range, so a finding on document
B doesn't fall back onto document A's root (whose span would otherwise
run to EOF).
"""
from __future__ import annotations

from typing import Any

from ...pipeline_graph import GraphEdge, GraphNode, PipelineGraph
from ...pipeline_graph_builders import register_builder
from .._yaml_lines import line_of, line_of_item
from .base import step_label

_ROOT_ID = "__root__"


def _step_id(step: dict[str, Any], idx: int) -> str:
    name = step.get("name")
    return name.strip() if isinstance(name, str) and name.strip() else f"step{idx}"


def _depends_on(step: dict[str, Any]) -> list[str]:
    dep = step.get("depends_on")
    if isinstance(dep, str):
        return [dep]
    if isinstance(dep, list):
        return [d for d in dep if isinstance(d, str)]
    return []


def _build_one(
    path: str, data: dict[str, Any], *, root_start: int, root_end: int | None,
) -> PipelineGraph:
    name = data.get("name")
    label = name.strip() if isinstance(name, str) and name.strip() else (
        path.rsplit("/", 1)[-1]
    )
    nodes: list[GraphNode] = [
        GraphNode(
            id=_ROOT_ID, kind="file", label=label, path=path,
            start_line=root_start, end_line=root_end, parent=None,
        ),
    ]
    edges: list[GraphEdge] = []

    steps_list = data.get("steps")
    if not isinstance(steps_list, list):
        return PipelineGraph(
            path=path, provider="drone",
            nodes=tuple(nodes), edges=(), root_id=_ROOT_ID,
        )

    indexed = [(i, s) for i, s in enumerate(steps_list) if isinstance(s, dict)]
    ids = {_step_id(s, i) for i, s in indexed}
    dag_mode = any(_depends_on(s) for _, s in indexed)
    prev: str | None = None
    for i, step in indexed:
        cur = _step_id(step, i)
        s_start = line_of_item(steps_list, i)
        s_next = line_of_item(steps_list, i + 1)
        # Last step ends at the document's end, not EOF, so a finding in a
        # later document can't land on this step.
        s_end = (s_next - 1) if s_next else root_end
        nodes.append(GraphNode(
            id=cur, kind="job", label=step_label(step, i), path=path,
            start_line=s_start, end_line=s_end, parent=_ROOT_ID,
        ))
        deps = _depends_on(step)
        if deps:
            for d in deps:
                if d in ids:
                    edges.append(GraphEdge(src=d, dst=cur, kind="needs"))
        elif not dag_mode and prev is not None:
            # Sequential default: chain off the previous step. (In DAG mode
            # a step with no ``depends_on`` starts immediately, no edge.)
            edges.append(GraphEdge(src=prev, dst=cur, kind="stage"))
        prev = cur

    return PipelineGraph(
        path=path, provider="drone",
        nodes=tuple(nodes), edges=tuple(edges), root_id=_ROOT_ID,
    )


def build_graphs(context: Any) -> list[PipelineGraph]:
    """One graph per ``kind: pipeline`` document, with each file-root
    bounded to its document's line range."""
    by_path: dict[str, list[dict[str, Any]]] = {}
    for pipe in getattr(context, "pipelines", []):
        data = getattr(pipe, "data", None)
        path = getattr(pipe, "path", "")
        if isinstance(data, dict) and path:
            by_path.setdefault(path, []).append(data)

    out: list[PipelineGraph] = []
    for path, docs in by_path.items():
        ranked = sorted(docs, key=lambda d: line_of(d) or 0)
        for i, data in enumerate(ranked):
            start = line_of(data) or 1
            nxt = line_of(ranked[i + 1]) if i + 1 < len(ranked) else None
            end = (nxt - 1) if nxt else None
            # The first document covers from line 1 so leading content isn't
            # orphaned above its root.
            out.append(_build_one(
                path, data, root_start=1 if i == 0 else start, root_end=end,
            ))
    return out


register_builder("drone", build_graphs)
