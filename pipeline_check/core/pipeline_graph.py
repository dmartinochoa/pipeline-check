"""Step-level pipeline DAG model, shared by the scanner and the HTML reporter.

A :class:`PipelineGraph` is a provider-neutral view of one CI/CD pipeline
file: jobs and steps as nodes, ``needs:`` / ``depends_on:`` / sequence as
edges. The per-provider builders under ``checks/<provider>/_graph.py`` produce
these from the parsed context (see :mod:`pipeline_check.core.pipeline_graph_builders`);
the HTML reporter renders them and overlays findings via :func:`attach_findings`.
IaC / SCA / cloud providers have no step DAG and produce no graphs.

The structural graph is immutable (frozen nodes/edges) so it can be cached and
shared; the finding overlay (worst severity + count per node) is computed into a
separate ``{node_id: NodeBadge}`` map at render time, never stored on the node.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .checks.base import Finding, Severity, severity_rank

__all__ = [
    "NodeKind",
    "EdgeKind",
    "GraphNode",
    "GraphEdge",
    "PipelineGraph",
    "NodeBadge",
    "attach_findings",
]

NodeKind = Literal["file", "stage", "job", "step"]
EdgeKind = Literal["needs", "sequence", "stage"]

# Deeper kinds win when several nodes contain the same source line.
_NODE_DEPTH: dict[str, int] = {"file": 0, "stage": 1, "job": 2, "step": 3}


@dataclass(frozen=True, slots=True)
class GraphNode:
    """One node in a pipeline graph.

    ``end_line`` of ``None`` means "extends to end of file": such a node
    (the file root, or the last job / step) contains every line at or
    after ``start_line``, so the deepest-kind match still resolves
    correctly. ``parent`` is the enclosing node's :attr:`id` (step -> job,
    job -> stage / file), used by the renderer to nest steps in a job box.
    """

    id: str
    kind: NodeKind
    label: str
    path: str
    start_line: int | None = None
    end_line: int | None = None
    parent: str | None = None


@dataclass(frozen=True, slots=True)
class GraphEdge:
    """A directed edge ``src -> dst`` between two node ids."""

    src: str
    dst: str
    kind: EdgeKind


@dataclass(frozen=True, slots=True)
class PipelineGraph:
    """The jobs / steps / edges of a single pipeline file."""

    path: str
    provider: str
    nodes: tuple[GraphNode, ...]
    edges: tuple[GraphEdge, ...]
    root_id: str


@dataclass
class NodeBadge:
    """The finding overlay for one node: worst severity + counts."""

    worst: Severity
    count: int
    breakdown: dict[str, int]


def _deepest_containing(
    graph: PipelineGraph, line: int,
) -> GraphNode | None:
    """Return the deepest-kind node whose line span contains *line*."""
    best: GraphNode | None = None
    best_depth = -1
    for node in graph.nodes:
        if node.start_line is None:
            continue
        end: float = node.end_line if node.end_line is not None else float("inf")
        if node.start_line <= line <= end:
            depth = _NODE_DEPTH[node.kind]
            if depth > best_depth:
                best, best_depth = node, depth
    return best


def attach_findings(
    graph: PipelineGraph, findings: list[Finding],
) -> dict[str, NodeBadge]:
    """Map each failing finding on ``graph.path`` to a node.

    A finding lands on the deepest node whose source-line span contains its
    :class:`~pipeline_check.core.checks.base.Location` line. A finding with no
    line on this file falls back to a matching ``job_anchors`` job, then to the
    file-root node. A multi-location finding badges every distinct node it
    touches (deduped per node). Returns ``{node_id: NodeBadge}`` for nodes that
    received at least one finding.
    """
    badges: dict[str, NodeBadge] = {}
    node_ids = {n.id for n in graph.nodes}

    def _add(node_id: str, sev: Severity) -> None:
        badge = badges.get(node_id)
        if badge is None:
            badges[node_id] = NodeBadge(
                worst=sev, count=1, breakdown={sev.value: 1},
            )
            return
        badge.count += 1
        badge.breakdown[sev.value] = badge.breakdown.get(sev.value, 0) + 1
        if severity_rank(sev) > severity_rank(badge.worst):
            badge.worst = sev

    for f in findings:
        if f.passed:
            continue
        on_file = f.resource == graph.path or any(
            loc.path == graph.path for loc in f.locations
        )
        lines = [
            loc.start_line for loc in f.locations
            if loc.path == graph.path and loc.start_line is not None
        ]
        if not lines and not on_file:
            continue  # this finding isn't about this file

        placed: set[str] = set()
        for line in lines:
            node = _deepest_containing(graph, line)
            if node is not None:
                placed.add(node.id)
        if not placed and not lines:
            # No positioned line on this file: fall back to a matching job
            # anchor, then to the file root. A finding that DOES carry a
            # line which landed in no node belongs to a different document
            # of a multi-document file (each graph's root is bounded to its
            # document's range), so it is left for that document's graph
            # rather than being pinned here by an anchor or the root.
            anchored = [jid for jid in f.job_anchors if jid in node_ids]
            placed.update(anchored or [graph.root_id])
        for node_id in placed:
            _add(node_id, f.severity)
    return badges
