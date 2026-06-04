"""GitHub Actions step-level pipeline-graph builder (DAG v2).

Walks every workflow's jobs and steps into a provider-neutral
:class:`~pipeline_check.core.pipeline_graph.PipelineGraph`: jobs as nodes,
their steps as child nodes, ``needs:`` as cross-job edges, and consecutive
steps as sequence edges. Line spans are derived from the line-aware loader so
the reporter can map each finding onto the deepest node that contains it.
"""
from __future__ import annotations

from typing import Any

from ...pipeline_graph import GraphEdge, GraphNode, PipelineGraph
from ...pipeline_graph_builders import register_builder
from .._yaml_lines import line_of, line_of_item
from .base import iter_jobs

_ROOT_ID = "__root__"


def _step_label(step: dict[str, Any]) -> str:
    name = step.get("name")
    if isinstance(name, str) and name.strip():
        return name
    uses = step.get("uses")
    if isinstance(uses, str) and uses.strip():
        return f"uses: {uses}"
    run = step.get("run")
    if isinstance(run, str) and run.strip():
        first = run.strip().splitlines()[0]
        return f"run: {first[:48]}"
    return "step"


def _need_ids(job: dict[str, Any], job_ids: set[str]) -> list[str]:
    needs = job.get("needs")
    if isinstance(needs, str):
        candidates = [needs]
    elif isinstance(needs, list):
        candidates = [n for n in needs if isinstance(n, str)]
    else:
        candidates = []
    return [n for n in candidates if n in job_ids]


def _build_one(path: str, data: dict[str, Any]) -> PipelineGraph:
    nodes: list[GraphNode] = [
        GraphNode(
            id=_ROOT_ID, kind="file", label=path.rsplit("/", 1)[-1],
            path=path, start_line=1, end_line=None, parent=None,
        ),
    ]
    edges: list[GraphEdge] = []

    jobs = list(iter_jobs(data))
    job_ids = {jid for jid, _ in jobs}
    # Order by source line so a job's span ends where the next job begins
    # (the last job extends to EOF via end_line=None).
    ordered = sorted(
        ((jid, job, line_of(job)) for jid, job in jobs),
        key=lambda t: (t[2] is None, t[2] or 0),
    )
    for idx, (job_id, job, start) in enumerate(ordered):
        next_start = ordered[idx + 1][2] if idx + 1 < len(ordered) else None
        job_end = (next_start - 1) if (next_start and start) else None
        nodes.append(GraphNode(
            id=job_id, kind="job", label=job_id, path=path,
            start_line=start, end_line=job_end, parent=_ROOT_ID,
        ))
        for dep in _need_ids(job, job_ids):
            edges.append(GraphEdge(src=dep, dst=job_id, kind="needs"))

        steps = job.get("steps")
        if not isinstance(steps, list):
            continue
        prev_step_id: str | None = None
        for i in range(len(steps)):
            step = steps[i]
            if not isinstance(step, dict):
                continue
            s_start = line_of_item(steps, i)
            s_next = line_of_item(steps, i + 1)
            s_end = (s_next - 1) if s_next else job_end
            sid = f"{job_id}#{i}"
            nodes.append(GraphNode(
                id=sid, kind="step", label=_step_label(step), path=path,
                start_line=s_start, end_line=s_end, parent=job_id,
            ))
            if prev_step_id is not None:
                edges.append(GraphEdge(
                    src=prev_step_id, dst=sid, kind="sequence",
                ))
            prev_step_id = sid

    return PipelineGraph(
        path=path, provider="github",
        nodes=tuple(nodes), edges=tuple(edges), root_id=_ROOT_ID,
    )


def build_graphs(context: Any) -> list[PipelineGraph]:
    """One graph per workflow in *context*."""
    out: list[PipelineGraph] = []
    for wf in getattr(context, "workflows", []):
        data = getattr(wf, "data", None)
        path = getattr(wf, "path", "")
        if isinstance(data, dict) and path:
            out.append(_build_one(path, data))
    return out


register_builder("github", build_graphs)
