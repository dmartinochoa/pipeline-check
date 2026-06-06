"""Azure DevOps Pipelines step-level pipeline-graph builder (DAG v2).

One graph per ``azure-pipelines.yml``. Jobs are ``job`` nodes and their
steps nest as ``step`` children (deployment-strategy phases are flattened
by ``iter_steps``). Edges come from Azure's two ``dependsOn`` levels:

* **Job ``dependsOn``** (by job name, resolved within the job's stage) ->
  a ``needs`` edge. A job with no ``dependsOn`` is an entry job of its
  stage.
* **Stage ordering**: stages run sequentially unless a stage declares its
  own ``dependsOn``. So each stage's entry jobs get a ``stage`` edge from
  every job of the predecessor stage(s), the explicit ``dependsOn:
  [names]`` ones when present, otherwise the immediately preceding stage.
  ``dependsOn: []`` opts a stage out of any predecessor.

This is the same wait-group shape the Buildkite builder uses, lifted to
the stage level. Flat ``jobs:`` pipelines have a single implicit stage
(job ``dependsOn`` only, no sequential chaining); a flat ``steps:``
pipeline becomes one synthetic job.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ...pipeline_graph import EdgeKind, GraphEdge, GraphNode, PipelineGraph
from ...pipeline_graph_builders import register_builder
from .._yaml_lines import line_of
from .base import iter_steps

_ROOT_ID = "__root__"


@dataclass(frozen=True, slots=True)
class _Stage:
    name: str | None
    dep: list[str] | None  # None = no dependsOn key (sequential default)
    jobs: list[tuple[str, dict[str, Any], str | None]]  # (id, job, bare name)


def _dep_list(val: Any) -> list[str]:
    if isinstance(val, str):
        return [val.strip()] if val.strip() else []
    if isinstance(val, list):
        return [v.strip() for v in val if isinstance(v, str) and v.strip()]
    return []


def _stage_dep(stage: dict[str, Any]) -> list[str] | None:
    return _dep_list(stage["dependsOn"]) if "dependsOn" in stage else None


def _bare_name(job: dict[str, Any]) -> str | None:
    for k in ("job", "deployment"):
        v = job.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def _step_label(step: dict[str, Any], fallback: str) -> str:
    dn = step.get("displayName")
    if isinstance(dn, str) and dn.strip():
        return dn.strip()
    for k in ("script", "bash", "pwsh", "powershell"):
        v = step.get(k)
        if isinstance(v, str) and v.strip():
            return f"{k}: {v.strip().splitlines()[0][:40]}"
    for k in ("task", "checkout", "template", "download", "publish"):
        v = step.get(k)
        if isinstance(v, str) and v.strip():
            return f"{k}: {v.strip()}"
    return fallback


def _gather(data: dict[str, Any]) -> tuple[list[_Stage], bool]:
    """Return ``(stages, staged)``. ``staged`` is True only for the
    ``stages:`` shape, where cross-stage sequencing applies."""
    stages = data.get("stages")
    if isinstance(stages, list):
        recs: list[_Stage] = []
        for i, stage in enumerate(stages):
            if not isinstance(stage, dict):
                continue
            sname = stage.get("stage")
            name = sname.strip() if isinstance(sname, str) and sname.strip() else f"stage{i}"
            jobs: list[tuple[str, dict[str, Any], str | None]] = []
            jobs_list = stage.get("jobs")
            if isinstance(jobs_list, list):
                for j, job in enumerate(jobs_list):
                    if isinstance(job, dict):
                        bare = _bare_name(job)
                        jobs.append((f"{name}.{bare or f'job{j}'}", job, bare))
            recs.append(_Stage(name=name, dep=_stage_dep(stage), jobs=jobs))
        return recs, True

    jobs_list = data.get("jobs")
    if isinstance(jobs_list, list):
        jobs = []
        for j, job in enumerate(jobs_list):
            if isinstance(job, dict):
                bare = _bare_name(job)
                jobs.append((bare or f"job{j}", job, bare))
        return [_Stage(name=None, dep=None, jobs=jobs)], False

    if isinstance(data.get("steps"), list):
        return [_Stage(name=None, dep=None, jobs=[("<pipeline>", data, None)])], False

    return [], False


def _assign_ends(
    starts: dict[str, int | None], fallback: int | None,
) -> dict[str, int | None]:
    ordered = sorted(starts, key=lambda k: (starts[k] is None, starts[k] or 0))
    ends: dict[str, int | None] = {}
    for i, k in enumerate(ordered):
        nxt = starts[ordered[i + 1]] if i + 1 < len(ordered) else None
        ends[k] = (nxt - 1) if (nxt and starts[k]) else fallback
    return ends


def _build_one(path: str, data: dict[str, Any]) -> PipelineGraph:
    nodes: list[GraphNode] = [
        GraphNode(
            id=_ROOT_ID, kind="file", label=path.rsplit("/", 1)[-1],
            path=path, start_line=1, end_line=None, parent=None,
        ),
    ]
    edges: list[GraphEdge] = []
    seen_edges: set[tuple[str, str, str]] = set()

    def _edge(src: str, dst: str, kind: EdgeKind) -> None:
        if src != dst and (src, dst, kind) not in seen_edges:
            seen_edges.add((src, dst, kind))
            edges.append(GraphEdge(src=src, dst=dst, kind=kind))

    stages, staged = _gather(data)

    # Dedup job ids across the whole file (first wins).
    seen_jobs: set[str] = set()
    for st in stages:
        deduped: list[tuple[str, dict[str, Any], str | None]] = []
        for jid, job, bare in st.jobs:
            if jid not in seen_jobs:
                seen_jobs.add(jid)
                deduped.append((jid, job, bare))
        st.jobs[:] = deduped

    job_starts = {
        jid: line_of(job) for st in stages for jid, job, _ in st.jobs
    }
    job_ends = _assign_ends(job_starts, None)
    stage_job_ids: dict[str, list[str]] = {
        st.name: [jid for jid, _, _ in st.jobs] for st in stages if st.name
    }

    entry_by_stage: list[list[str]] = []
    for st in stages:
        name_map = {bare: jid for jid, _job, bare in st.jobs if bare}
        entries: list[str] = []
        for jid, job, bare in st.jobs:
            nodes.append(GraphNode(
                id=jid, kind="job", label=bare or jid, path=path,
                start_line=job_starts[jid], end_line=job_ends[jid],
                parent=_ROOT_ID,
            ))
            steps = [(lbl, s) for lbl, s in iter_steps(job)]
            step_starts = {
                f"{jid}#{i}": line_of(s) for i, (_lbl, s) in enumerate(steps)
            }
            step_ends = _assign_ends(step_starts, job_ends[jid])
            prev: str | None = None
            for i, (lbl, step) in enumerate(steps):
                sid = f"{jid}#{i}"
                nodes.append(GraphNode(
                    id=sid, kind="step", label=_step_label(step, lbl), path=path,
                    start_line=step_starts[sid], end_line=step_ends[sid],
                    parent=jid,
                ))
                if prev is not None:
                    _edge(prev, sid, "sequence")
                prev = sid

            resolved = [
                name_map[d] for d in _dep_list(job.get("dependsOn"))
                if name_map.get(d) and name_map[d] != jid
            ]
            for tgt in resolved:
                _edge(tgt, jid, "needs")
            if not resolved:
                entries.append(jid)
        entry_by_stage.append(entries)

    # Cross-stage sequencing (the ``stages:`` shape only).
    if staged:
        for k, st in enumerate(stages):
            if st.dep is not None:
                preds = [j for sn in st.dep for j in stage_job_ids.get(sn, [])]
            elif k > 0:
                preds = [jid for jid, _, _ in stages[k - 1].jobs]
            else:
                preds = []
            for entry in entry_by_stage[k]:
                for p in preds:
                    _edge(p, entry, "stage")

    return PipelineGraph(
        path=path, provider="azure",
        nodes=tuple(nodes), edges=tuple(edges), root_id=_ROOT_ID,
    )


def build_graphs(context: Any) -> list[PipelineGraph]:
    """One graph per Azure pipeline file in *context*."""
    out: list[PipelineGraph] = []
    for pipe in getattr(context, "pipelines", []):
        data = getattr(pipe, "data", None)
        path = getattr(pipe, "path", "")
        if isinstance(data, dict) and path:
            out.append(_build_one(path, data))
    return out


register_builder("azure", build_graphs)
