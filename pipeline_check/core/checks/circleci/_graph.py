"""CircleCI step-level pipeline-graph builder (DAG v2).

Builds one graph per ``.circleci/config.yml``: the jobs defined under
``jobs:`` are nodes, their steps are child nodes, and the
``workflows.<name>.jobs[].requires`` references become cross-job edges,
unioned across every workflow (a config can run the same job in more than
one workflow with different ``requires``). Line spans come from the
line-aware loader so each finding overlays onto the job that contains it.

Unlike GitHub / GitLab, the dependency structure lives in the
``workflows:`` section rather than on the jobs themselves, so a job
referenced by an alias or by an orb (not a ``jobs:`` entry) is dropped
from the edge set rather than guessed at.
"""
from __future__ import annotations

from typing import Any

from ...pipeline_graph import GraphEdge, GraphNode, PipelineGraph
from ...pipeline_graph_builders import register_builder
from .._yaml_lines import line_of, line_of_item
from .base import iter_jobs, iter_workflow_jobs

_ROOT_ID = "__root__"


def _step_label(step: Any) -> str:
    if isinstance(step, str):
        return step  # a bare step such as ``checkout``
    if isinstance(step, dict):
        run = step.get("run")
        if run is not None:
            if isinstance(run, str):
                return f"run: {run.strip().splitlines()[0][:48]}"
            if isinstance(run, dict):
                name = run.get("name")
                if isinstance(name, str) and name.strip():
                    return f"run: {name}"
                cmd = run.get("command")
                if isinstance(cmd, str) and cmd.strip():
                    return f"run: {cmd.strip().splitlines()[0][:48]}"
            return "run"
        key = next((k for k in step if isinstance(k, str)), None)
        if key:
            return key  # e.g. ``checkout`` / ``save_cache`` / an orb command
    return "step"


def _requires(cfg: dict[str, Any]) -> list[str]:
    req = cfg.get("requires")
    if isinstance(req, str):
        return [req]
    if isinstance(req, list):
        return [r for r in req if isinstance(r, str)]
    return []


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
        steps = job.get("steps")
        if not isinstance(steps, list):
            continue
        prev_sid: str | None = None
        for i, step in enumerate(steps):
            s_start = line_of_item(steps, i)
            s_next = line_of_item(steps, i + 1)
            s_end = (s_next - 1) if s_next else job_end
            sid = f"{job_id}#{i}"
            nodes.append(GraphNode(
                id=sid, kind="step", label=_step_label(step), path=path,
                start_line=s_start, end_line=s_end, parent=job_id,
            ))
            if prev_sid is not None:
                edges.append(GraphEdge(src=prev_sid, dst=sid, kind="sequence"))
            prev_sid = sid

    # ``requires:`` edges from the workflows, unioned + deduped. Only
    # references to real ``jobs:`` entries become edges.
    seen: set[tuple[str, str]] = set()
    for _wf, job_name, cfg in iter_workflow_jobs(data):
        if job_name not in job_ids:
            continue
        for req in _requires(cfg):
            if req in job_ids and (req, job_name) not in seen:
                seen.add((req, job_name))
                edges.append(GraphEdge(src=req, dst=job_name, kind="needs"))

    return PipelineGraph(
        path=path, provider="circleci",
        nodes=tuple(nodes), edges=tuple(edges), root_id=_ROOT_ID,
    )


def build_graphs(context: Any) -> list[PipelineGraph]:
    """One graph per CircleCI config in *context*."""
    out: list[PipelineGraph] = []
    for pipe in getattr(context, "pipelines", []):
        data = getattr(pipe, "data", None)
        path = getattr(pipe, "path", "")
        if isinstance(data, dict) and path:
            out.append(_build_one(path, data))
    return out


register_builder("circleci", build_graphs)
