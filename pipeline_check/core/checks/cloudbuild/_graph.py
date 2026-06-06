"""GCP Cloud Build step-level pipeline-graph builder (DAG v2).

A ``cloudbuild.yaml`` is a flat list of build steps that run sequentially
by default; ``waitFor`` turns it into a DAG. Each step is the unit of
work, so it maps to a ``job`` node (the renderer lays jobs out as boxes,
``step`` nodes only render nested inside a job). Edges:

  * ``waitFor: [id, ...]`` references other steps by their ``id`` and
    becomes ``needs`` edges (filtered to real step ids);
  * ``waitFor: ['-']`` starts a step immediately, no incoming edge;
  * a step with no ``waitFor`` waits for the previous step (the
    sequential default), drawn as a ``stage`` edge.

The sequential default actually waits for *every* prior step, but a chain
from the previous one gives the same layered ordering, so we draw the
chain rather than an O(n^2) fan-in.
"""
from __future__ import annotations

from typing import Any

from ...pipeline_graph import GraphEdge, GraphNode, PipelineGraph
from ...pipeline_graph_builders import register_builder
from .._yaml_lines import line_of_item
from .base import iter_steps

_ROOT_ID = "__root__"


def _step_id(step: dict[str, Any], idx: int) -> str:
    sid = step.get("id")
    return sid.strip() if isinstance(sid, str) and sid.strip() else f"step{idx}"


def _step_label(step: dict[str, Any], idx: int) -> str:
    sid = step.get("id")
    if isinstance(sid, str) and sid.strip():
        return sid.strip()
    name = step.get("name")  # the builder image; basename is the readable bit
    if isinstance(name, str) and name.strip():
        return name.strip().rsplit("/", 1)[-1][:40]
    return f"step{idx}"


def _wait_for(step: dict[str, Any]) -> list[str] | None:
    """``waitFor`` as a list of step ids, or ``None`` when the key is absent
    (which selects the sequential default)."""
    w = step.get("waitFor")
    if isinstance(w, str):
        return [w]
    if isinstance(w, list):
        return [x for x in w if isinstance(x, str)]
    return None


def _build_one(path: str, data: dict[str, Any]) -> PipelineGraph:
    nodes: list[GraphNode] = [
        GraphNode(
            id=_ROOT_ID, kind="file", label=path.rsplit("/", 1)[-1],
            path=path, start_line=1, end_line=None, parent=None,
        ),
    ]
    edges: list[GraphEdge] = []

    steps_list = data.get("steps")
    if not isinstance(steps_list, list):
        return PipelineGraph(
            path=path, provider="cloudbuild",
            nodes=tuple(nodes), edges=(), root_id=_ROOT_ID,
        )

    indexed = list(iter_steps(data))  # (original_index, step_dict)
    ids = {_step_id(s, i) for i, s in indexed}
    prev: str | None = None
    for i, step in indexed:
        cur = _step_id(step, i)
        s_start = line_of_item(steps_list, i)
        s_next = line_of_item(steps_list, i + 1)
        s_end = (s_next - 1) if s_next else None
        nodes.append(GraphNode(
            id=cur, kind="job", label=_step_label(step, i), path=path,
            start_line=s_start, end_line=s_end, parent=_ROOT_ID,
        ))
        wait = _wait_for(step)
        if wait is None:
            # Sequential default: wait for the previous step.
            if prev is not None:
                edges.append(GraphEdge(src=prev, dst=cur, kind="stage"))
        else:
            for dep in wait:
                if dep != "-" and dep in ids:
                    edges.append(GraphEdge(src=dep, dst=cur, kind="needs"))
            # ``waitFor: ['-']`` (or only unknown ids) leaves no incoming
            # edge, the step starts immediately.
        prev = cur

    return PipelineGraph(
        path=path, provider="cloudbuild",
        nodes=tuple(nodes), edges=tuple(edges), root_id=_ROOT_ID,
    )


def build_graphs(context: Any) -> list[PipelineGraph]:
    """One graph per ``cloudbuild.yaml`` in *context*."""
    out: list[PipelineGraph] = []
    for pipe in getattr(context, "pipelines", []):
        data = getattr(pipe, "data", None)
        path = getattr(pipe, "path", "")
        if isinstance(data, dict) and path:
            out.append(_build_one(path, data))
    return out


register_builder("cloudbuild", build_graphs)
