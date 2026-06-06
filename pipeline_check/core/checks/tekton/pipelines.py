"""Tekton orchestrator. Auto-discovers TKN-* rules under ``rules/``.

Each rule receives the full :class:`TektonContext` and emits a single
aggregated Finding spanning every doc it cares about. This mirrors
the Kubernetes orchestrator's shape. Tekton manifests live in
multi-doc YAML, and the per-doc / per-kind branching belongs inside
the rule, not in the orchestrator.

The per-step rules (TKN-002 / TKN-003) attribute their offenders via
``job_anchors`` (``<Kind>/<name>:<step>``) rather than ``locations``, so
their aggregated findings would otherwise reach the reporters and the
pipeline graph with no source location. :func:`_backfill_anchor_locations`
resolves those anchors back to a document + step line once, here, instead
of in every rule, matching the ``Location`` shape TKN-001 sets natively.
"""
from __future__ import annotations

from .._yaml_lines import line_of
from ..base import Finding, Location
from ..rule import apply_rule_metadata, discover_rules
from .base import (
    TektonBaseCheck,
    TektonContext,
    TektonDoc,
    pipeline_tasks,
    step_name,
    task_steps,
)


class TektonChecks(TektonBaseCheck):

    def __init__(
        self, ctx: TektonContext, target: str | None = None,
    ) -> None:
        super().__init__(ctx, target)
        self._rules = discover_rules(
            "pipeline_check.core.checks.tekton.rules"
        )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        doc_index = {(d.kind, d.name): d for d in self.ctx.docs}
        for rule, check_fn in self._rules:
            finding = check_fn(self.ctx)
            apply_rule_metadata(finding, rule)
            _backfill_anchor_locations(finding, doc_index)
            findings.append(finding)
        return findings


def _backfill_anchor_locations(
    finding: Finding, doc_index: dict[tuple[str, str], TektonDoc],
) -> None:
    """Populate ``finding.locations`` from its ``job_anchors``.

    No-op when the finding already carries locations (e.g. TKN-001) or has
    no anchors. Anchors that don't resolve to a known document are skipped.
    """
    if finding.locations or not finding.job_anchors:
        return
    locs: list[Location] = []
    for anchor in finding.job_anchors:
        loc = _resolve_anchor(anchor, doc_index)
        if loc is not None:
            locs.append(loc)
    if locs:
        finding.locations = locs


def _resolve_anchor(
    anchor: str, doc_index: dict[tuple[str, str], TektonDoc],
) -> Location | None:
    """Resolve a ``<Kind>/<name>:<step>`` anchor to a :class:`Location`."""
    head, sep, step = anchor.partition(":")
    kind, slash, name = head.partition("/")
    if not slash:
        return None
    doc = doc_index.get((kind, name))
    if doc is None:
        return None
    line: int | None = None
    if sep and step:
        for idx, st in enumerate(task_steps(doc)):
            if step_name(st, idx) == step:
                line = line_of(st)
                break
        if line is None:
            for idx, task in enumerate(pipeline_tasks(doc)):
                tn = task.get("name")
                ident = (
                    tn.strip() if isinstance(tn, str) and tn.strip()
                    else f"tasks[{idx}]"
                )
                if ident == step:
                    line = line_of(task)
                    break
    if line is None:
        line = line_of(doc.data)
    return Location(
        path=doc.path, start_line=line, end_line=line,
        doc_index=doc.doc_index,
    )
