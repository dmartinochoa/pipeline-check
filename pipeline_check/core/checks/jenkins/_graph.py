"""Jenkins step-level pipeline-graph builder (DAG v2).

Jenkinsfiles are Groovy, not YAML, so there is no parsed step tree. The
provider already locates ``stage('Name') { ... }`` blocks with a
depth-aware brace walk; this builder reuses that walk to recover each
stage's character range, then keeps only the **top-level** stages (a
stage whose range is not contained in another stage's body). Those are
the main pipeline stages, which declarative Jenkins runs in order, so
they chain via ``stage`` edges.

Nested stages (the branches of a ``parallel { ... }`` block, or
declarative sub-stages) fold into their enclosing top-level stage rather
than becoming their own nodes. That keeps the main flow correct without
inventing edges the flat stage list can't justify; a finding inside a
nested stage still lands on the enclosing stage's node (its range covers
the whole body) or, failing that, the file root.
"""
from __future__ import annotations

from typing import Any

from ...pipeline_graph import GraphEdge, GraphNode, PipelineGraph
from ...pipeline_graph_builders import register_builder
from .base import _STAGE_HEAD_RE, _skip_string

_ROOT_ID = "__root__"


def _stage_ranges(text: str) -> list[tuple[str, int, int]]:
    """Return ``(name, start, end)`` char ranges for every stage block.

    Mirrors ``base._extract_stages`` (same string-skipping brace walk) but
    keeps offsets instead of bodies so containment and line numbers can be
    derived.
    """
    out: list[tuple[str, int, int]] = []
    for head in _STAGE_HEAD_RE.finditer(text):
        i = head.end()
        depth = 1
        while i < len(text) and depth > 0:
            ch = text[i]
            if ch in ('"', "'"):
                i = _skip_string(text, i) + 1
                continue
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            i += 1
        out.append((head.group(1), head.start(), i))
    return out


def _top_level(ranges: list[tuple[str, int, int]]) -> list[tuple[str, int, int]]:
    """Keep only stages whose range is not contained in another stage."""
    return [
        (name, s, e) for k, (name, s, e) in enumerate(ranges)
        if not any(
            s2 < s and e <= e2
            for j, (_n, s2, e2) in enumerate(ranges) if j != k
        )
    ]


def _line_at(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _build_one(path: str, text: str) -> PipelineGraph:
    nodes: list[GraphNode] = [
        GraphNode(
            id=_ROOT_ID, kind="file", label=path.rsplit("/", 1)[-1],
            path=path, start_line=1, end_line=None, parent=None,
        ),
    ]
    edges: list[GraphEdge] = []

    stages = sorted(_top_level(_stage_ranges(text)), key=lambda t: t[1])
    used: set[str] = set()
    ids: list[str] = []
    for idx, (name, start, end) in enumerate(stages):
        base = name.strip() or f"stage{idx}"
        nid = base if base not in used else f"{base}#{idx}"
        used.add(nid)
        ids.append(nid)
        nodes.append(GraphNode(
            id=nid, kind="job", label=name.strip() or base, path=path,
            start_line=_line_at(text, start),
            # end of the block's closing brace; -1 keeps the next stage's
            # opening line out of this node's span.
            end_line=max(_line_at(text, max(end - 1, 0)), _line_at(text, start)),
            parent=_ROOT_ID,
        ))

    # ``ids[1:]`` is intentionally one shorter, so pair consecutive stages
    # non-strictly (strict=True would raise on the length mismatch).
    for prev, cur in zip(ids, ids[1:], strict=False):
        edges.append(GraphEdge(src=prev, dst=cur, kind="stage"))

    return PipelineGraph(
        path=path, provider="jenkins",
        nodes=tuple(nodes), edges=tuple(edges), root_id=_ROOT_ID,
    )


def build_graphs(context: Any) -> list[PipelineGraph]:
    """One graph per Jenkinsfile in *context*."""
    out: list[PipelineGraph] = []
    for jf in getattr(context, "files", []):
        path = getattr(jf, "path", "")
        text = getattr(jf, "text", "")
        if path and isinstance(text, str):
            out.append(_build_one(path, text))
    return out


register_builder("jenkins", build_graphs)
