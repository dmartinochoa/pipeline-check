"""GitLab CI step-level pipeline-graph builder (DAG v2).

Walks every ``.gitlab-ci.yml``'s jobs into a provider-neutral
:class:`~pipeline_check.core.pipeline_graph.PipelineGraph`: jobs as nodes,
``needs:`` as cross-job edges, and stage ordering as ``stage`` edges (a job
with no explicit ``needs`` waits for the previous stage, GitLab's default
execution model). Line spans come from the line-aware loader so the reporter
maps each finding onto the job that contains it. GitLab jobs carry a ``script``
list rather than named steps, so jobs are the leaf nodes.
"""
from __future__ import annotations

from typing import Any

from ...pipeline_graph import GraphEdge, GraphNode, PipelineGraph
from ...pipeline_graph_builders import register_builder
from .._yaml_lines import line_of
from .base import iter_jobs

_ROOT_ID = "__root__"

# GitLab's default stage order when ``stages:`` is omitted. ``.pre`` always
# runs first and ``.post`` always last, regardless of the declared list.
_DEFAULT_STAGES = ("build", "test", "deploy")
_DEFAULT_JOB_STAGE = "test"


def _stage_order(data: dict[str, Any]) -> list[str]:
    raw = data.get("stages")
    declared = (
        [s for s in raw if isinstance(s, str)]
        if isinstance(raw, list) else list(_DEFAULT_STAGES)
    )
    middle = [s for s in declared if s not in (".pre", ".post")]
    return [".pre", *middle, ".post"]


def _job_stage(job: dict[str, Any]) -> str:
    stage = job.get("stage")
    return stage if isinstance(stage, str) else _DEFAULT_JOB_STAGE


def _need_ids(job: dict[str, Any], job_ids: set[str]) -> list[str]:
    """Job names from ``needs:`` (a list of strings or ``{job: name}`` dicts,
    or a bare string), keeping only references to jobs that actually exist."""
    needs = job.get("needs")
    out: list[str] = []
    if isinstance(needs, list):
        for n in needs:
            if isinstance(n, str):
                out.append(n)
            elif isinstance(n, dict) and isinstance(n.get("job"), str):
                out.append(n["job"])
    elif isinstance(needs, str):
        out.append(needs)
    return [n for n in out if n in job_ids]


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

    stage_order = _stage_order(data)
    stage_rank = {s: i for i, s in enumerate(stage_order)}
    job_stage = {jid: _job_stage(job) for jid, job, _ in ordered}
    jobs_by_stage: dict[str, list[str]] = {}
    for jid in (jid for jid, _, _ in ordered):
        jobs_by_stage.setdefault(job_stage[jid], []).append(jid)

    for idx, (job_id, job, start) in enumerate(ordered):
        next_start = ordered[idx + 1][2] if idx + 1 < len(ordered) else None
        job_end = (next_start - 1) if (next_start and start) else None
        nodes.append(GraphNode(
            id=job_id, kind="job", label=job_id, path=path,
            start_line=start, end_line=job_end, parent=_ROOT_ID,
        ))
        if "needs" in job:
            # Explicit DAG: the job starts when its needs complete, ignoring
            # stage order. ``needs: []`` means "no dependencies" (no edges).
            for dep in _need_ids(job, job_ids):
                edges.append(GraphEdge(src=dep, dst=job_id, kind="needs"))
            continue
        # Otherwise the job waits for every job in the nearest earlier
        # non-empty stage (GitLab's stage-by-stage default).
        rank = stage_rank.get(job_stage[job_id])
        if rank is None:
            continue
        for prev_rank in range(rank - 1, -1, -1):
            deps = jobs_by_stage.get(stage_order[prev_rank], [])
            if deps:
                edges.extend(
                    GraphEdge(src=dep, dst=job_id, kind="stage") for dep in deps
                )
                break

    return PipelineGraph(
        path=path, provider="gitlab",
        nodes=tuple(nodes), edges=tuple(edges), root_id=_ROOT_ID,
    )


def build_graphs(context: Any) -> list[PipelineGraph]:
    """One graph per ``.gitlab-ci.yml`` pipeline in *context*."""
    out: list[PipelineGraph] = []
    for pipe in getattr(context, "pipelines", []):
        data = getattr(pipe, "data", None)
        path = getattr(pipe, "path", "")
        if isinstance(data, dict) and path:
            out.append(_build_one(path, data))
    return out


register_builder("gitlab", build_graphs)
