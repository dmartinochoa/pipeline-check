"""Buildkite step-level pipeline-graph builder (DAG v2).

A Buildkite pipeline file is a single document with a flat ``steps:`` list.
Each command step is the unit of work, so it maps to a ``job`` node (the
renderer lays jobs out as boxes). Two things shape the edges:

* ``depends_on`` names another step by its ``key`` and is the explicit
  dependency: ``depends_on`` -> ``needs`` edge. A step that declares
  ``depends_on`` waits only for those steps, so it gets no implicit edge.
* ``wait`` / ``block`` / ``input`` steps are barriers. Steps run in
  parallel between barriers, and every step after a barrier waits for
  every step before it. So a step with no ``depends_on`` gets a ``stage``
  edge from each step in the previous wait-group (which conveys the
  barrier without implying a false order between the parallel siblings).

``group`` steps are flattened: their children join the current wait-group
as ordinary command steps, mirroring ``iter_command_steps``. ``trigger``
steps launch another pipeline and carry no build work of their own, so
they are skipped (also matching ``iter_command_steps``).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ...pipeline_graph import EdgeKind, GraphEdge, GraphNode, PipelineGraph
from ...pipeline_graph_builders import register_builder
from .._yaml_lines import line_of
from .base import step_label

_ROOT_ID = "__root__"
_BARRIER_KEYS = ("wait", "waiter", "block", "input")


@dataclass(frozen=True, slots=True)
class _StepRec:
    id: str
    label: str
    start_line: int | None
    deps: tuple[str, ...]
    group: int


def _step_id(step: dict[str, Any], idx: int) -> str:
    key = step.get("key")
    return key.strip() if isinstance(key, str) and key.strip() else f"step{idx}"


def _depends_on(step: dict[str, Any]) -> tuple[str, ...]:
    """Return the step keys *step* depends on.

    ``depends_on`` is a string, a list of strings, or a list of
    ``{step: key, allow_failure: bool}`` dicts. Normalize to a tuple of
    referenced keys.
    """
    dep = step.get("depends_on")
    if isinstance(dep, str):
        return (dep.strip(),) if dep.strip() else ()
    if not isinstance(dep, list):
        return ()
    out: list[str] = []
    for d in dep:
        if isinstance(d, str) and d.strip():
            out.append(d.strip())
        elif isinstance(d, dict):
            s = d.get("step")
            if isinstance(s, str) and s.strip():
                out.append(s.strip())
    return tuple(out)


def _walk_steps(steps: list[Any]) -> list[_StepRec]:
    """Flatten *steps* into command-step records, tracking wait-groups.

    ``wait`` / ``block`` / ``input`` barriers bump the group counter;
    ``group`` containers flatten their children into the current group.
    """
    records: list[_StepRec] = []
    group = 0
    idx = 0
    for raw in steps:
        if isinstance(raw, str):
            if raw.strip() in ("wait", "waiter"):
                group += 1
            idx += 1
            continue
        if not isinstance(raw, dict):
            idx += 1
            continue
        if any(k in raw for k in _BARRIER_KEYS):
            group += 1
            idx += 1
            continue
        if "trigger" in raw:
            idx += 1
            continue
        if "group" in raw and isinstance(raw.get("steps"), list):
            for child in raw["steps"]:
                if isinstance(child, dict) and not any(
                    k in child for k in _BARRIER_KEYS
                ) and "trigger" not in child:
                    records.append(_StepRec(
                        id=_step_id(child, idx), label=step_label(child, idx),
                        start_line=line_of(child), deps=_depends_on(child),
                        group=group,
                    ))
                    idx += 1
            continue
        records.append(_StepRec(
            id=_step_id(raw, idx), label=step_label(raw, idx),
            start_line=line_of(raw), deps=_depends_on(raw), group=group,
        ))
        idx += 1
    return records


def _build_one(path: str, data: dict[str, Any]) -> PipelineGraph:
    nodes: list[GraphNode] = [
        GraphNode(
            id=_ROOT_ID, kind="file", label=path.rsplit("/", 1)[-1],
            path=path, start_line=1, end_line=None, parent=None,
        ),
    ]
    edges: list[GraphEdge] = []

    steps = data.get("steps")
    if not isinstance(steps, list):
        return PipelineGraph(
            path=path, provider="buildkite",
            nodes=tuple(nodes), edges=(), root_id=_ROOT_ID,
        )

    # First record per id wins (keys are unique in a valid pipeline; this
    # guards against a duplicated key collapsing two boxes into one).
    all_ids: set[str] = set()
    records: list[_StepRec] = []
    for r in _walk_steps(steps):
        if r.id not in all_ids:
            all_ids.add(r.id)
            records.append(r)

    # End-of-span: a job ends where the next job (by source line) begins;
    # the last job runs to EOF (end_line=None).
    ordered = sorted(
        records, key=lambda r: (r.start_line is None, r.start_line or 0),
    )
    ends: dict[str, int | None] = {}
    for i, r in enumerate(ordered):
        nxt = ordered[i + 1].start_line if i + 1 < len(ordered) else None
        ends[r.id] = (nxt - 1) if (nxt and r.start_line) else None

    for r in records:
        nodes.append(GraphNode(
            id=r.id, kind="job", label=r.label, path=path,
            start_line=r.start_line, end_line=ends[r.id], parent=_ROOT_ID,
        ))

    # Edges. Explicit ``depends_on`` -> ``needs``; otherwise the wait-group
    # barrier -> ``stage`` from every step in the previous (non-empty)
    # wait-group. Iterating groups in order makes ``prev_ids`` bridge empty
    # groups (back-to-back barriers act as one).
    by_group: dict[int, list[_StepRec]] = {}
    for r in records:
        by_group.setdefault(r.group, []).append(r)

    seen_edges: set[tuple[str, str, str]] = set()

    def _edge(src: str, dst: str, kind: EdgeKind) -> None:
        key = (src, dst, kind)
        if key not in seen_edges:
            seen_edges.add(key)
            edges.append(GraphEdge(src=src, dst=dst, kind=kind))

    prev_ids: list[str] = []
    for g in sorted(by_group):
        recs = by_group[g]
        for r in recs:
            if r.deps:
                for d in r.deps:
                    if d in all_ids:
                        _edge(d, r.id, "needs")
            else:
                for p in prev_ids:
                    _edge(p, r.id, "stage")
        prev_ids = [r.id for r in recs]

    return PipelineGraph(
        path=path, provider="buildkite",
        nodes=tuple(nodes), edges=tuple(edges), root_id=_ROOT_ID,
    )


def build_graphs(context: Any) -> list[PipelineGraph]:
    """One graph per Buildkite pipeline file in *context*."""
    out: list[PipelineGraph] = []
    for pipe in getattr(context, "pipelines", []):
        data = getattr(pipe, "data", None)
        path = getattr(pipe, "path", "")
        if isinstance(data, dict) and path:
            out.append(_build_one(path, data))
    return out


register_builder("buildkite", build_graphs)
