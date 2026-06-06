"""Bitbucket Pipelines step-level pipeline-graph builder (DAG v2).

One graph per ``bitbucket-pipelines.yml``. A file holds several pipeline
*definitions* under ``pipelines:`` (``default`` plus the ``branches`` /
``pull-requests`` / ``custom`` / ``tags`` maps); they are alternative
entry points, not connected to each other, so they render as independent
chains in the one graph. Keeping them in a single graph (rather than one
per definition) means a finding with no line still badges a single file
root instead of double-counting onto every definition.

Bitbucket ordering is positional, there is no ``depends_on``:

* a plain ``step`` is its own group,
* a ``parallel`` block is one group whose steps run concurrently (no edge
  between them),
* a ``stage`` runs its steps sequentially, so each inner step is its own
  group.

Consecutive groups within a definition are joined by a ``stage`` edge from
every step of the previous group to every step of the next, the same
wait-group shape the Buildkite / Azure builders use.
"""
from __future__ import annotations

from typing import Any

from ...pipeline_graph import GraphEdge, GraphNode, PipelineGraph
from ...pipeline_graph_builders import register_builder
from .._yaml_lines import line_of

_ROOT_ID = "__root__"

# One group of steps that start together (a parallel block, or a singleton):
# each tuple is (node id, label, source line, step dict).
_Group = list[tuple[str, str, "int | None", dict[str, Any]]]


def _step_label(step: dict[str, Any], fallback: str) -> str:
    name = step.get("name")
    return name.strip() if isinstance(name, str) and name.strip() else fallback


def _definition_groups(prefix: str, items: list[Any]) -> list[_Group]:
    """Split one definition's entry list into ordered step groups."""
    groups: list[_Group] = []
    for idx, entry in enumerate(items):
        if not isinstance(entry, dict):
            continue
        if isinstance(entry.get("step"), dict):
            s = entry["step"]
            nid = f"{prefix}[{idx}]"
            groups.append([(nid, _step_label(s, nid), line_of(s), s)])
        elif "parallel" in entry:
            par = entry["parallel"]
            par_steps = par.get("steps") if isinstance(par, dict) else par
            grp: _Group = []
            if isinstance(par_steps, list):
                for jdx, psub in enumerate(par_steps):
                    if isinstance(psub, dict) and isinstance(psub.get("step"), dict):
                        s = psub["step"]
                        nid = f"{prefix}[{idx}].parallel[{jdx}]"
                        grp.append((nid, _step_label(s, nid), line_of(s), s))
            if grp:
                groups.append(grp)
        elif isinstance(entry.get("stage"), dict):
            inner = entry["stage"].get("steps")
            if isinstance(inner, list):
                for jdx, sub in enumerate(inner):
                    if isinstance(sub, dict) and isinstance(sub.get("step"), dict):
                        s = sub["step"]
                        nid = f"{prefix}[{idx}].stage[{jdx}]"
                        groups.append([(nid, _step_label(s, nid), line_of(s), s)])
    return groups


def _iter_definitions(pipelines: dict[str, Any]) -> list[tuple[str, list[Any]]]:
    """Yield ``(definition_label, entry_list)`` for every pipeline definition."""
    out: list[tuple[str, list[Any]]] = []
    for category, value in pipelines.items():
        if isinstance(value, list):
            out.append((str(category), value))
        elif isinstance(value, dict):
            for sub, items in value.items():
                if isinstance(items, list):
                    out.append((f"{category}.{sub}", items))
    return out


def _build_one(path: str, data: dict[str, Any]) -> PipelineGraph:
    nodes: list[GraphNode] = [
        GraphNode(
            id=_ROOT_ID, kind="file", label=path.rsplit("/", 1)[-1],
            path=path, start_line=1, end_line=None, parent=None,
        ),
    ]
    edges: list[GraphEdge] = []

    pipelines = data.get("pipelines")
    if not isinstance(pipelines, dict):
        return PipelineGraph(
            path=path, provider="bitbucket",
            nodes=tuple(nodes), edges=(), root_id=_ROOT_ID,
        )

    definitions = [
        (label, _definition_groups(label, items))
        for label, items in _iter_definitions(pipelines)
    ]

    # End-of-span across every step node (first id wins on a collision).
    starts: dict[str, int | None] = {}
    for _label, groups in definitions:
        for grp in groups:
            for nid, _lbl, line, _s in grp:
                starts.setdefault(nid, line)
    ordered = sorted(starts, key=lambda k: (starts[k] is None, starts[k] or 0))
    ends: dict[str, int | None] = {}
    for i, nid in enumerate(ordered):
        nxt = starts[ordered[i + 1]] if i + 1 < len(ordered) else None
        ends[nid] = (nxt - 1) if (nxt and starts[nid]) else None

    seen_nodes: set[str] = set()
    seen_edges: set[tuple[str, str]] = set()
    for _label, groups in definitions:
        prev_ids: list[str] = []
        for grp in groups:
            cur_ids: list[str] = []
            for nid, lbl, line, _s in grp:
                cur_ids.append(nid)
                if nid not in seen_nodes:
                    seen_nodes.add(nid)
                    nodes.append(GraphNode(
                        id=nid, kind="job", label=lbl, path=path,
                        start_line=line, end_line=ends.get(nid),
                        parent=_ROOT_ID,
                    ))
                for p in prev_ids:
                    if (p, nid) not in seen_edges:
                        seen_edges.add((p, nid))
                        edges.append(GraphEdge(src=p, dst=nid, kind="stage"))
            prev_ids = cur_ids

    return PipelineGraph(
        path=path, provider="bitbucket",
        nodes=tuple(nodes), edges=tuple(edges), root_id=_ROOT_ID,
    )


def build_graphs(context: Any) -> list[PipelineGraph]:
    """One graph per Bitbucket pipeline file in *context*."""
    out: list[PipelineGraph] = []
    for pipe in getattr(context, "pipelines", []):
        data = getattr(pipe, "data", None)
        path = getattr(pipe, "path", "")
        if isinstance(data, dict) and path:
            out.append(_build_one(path, data))
    return out


register_builder("bitbucket", build_graphs)
