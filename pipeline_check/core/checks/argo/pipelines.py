"""Argo Workflows orchestrator. Auto-discovers ARGO-* rules.

Each rule receives the full :class:`ArgoContext` and emits a single
aggregated Finding. Mirrors the Tekton / Kubernetes orchestrator
shape so rules that span multiple docs can correlate without the
orchestrator needing to know which is which.

The per-template rules (ARGO-005 parameter injection, ARGO-017 resource
manifest injection) attribute their offenders via ``job_anchors``
(``<Kind>/<name>:<template>``) rather than ``locations``, so their
aggregated findings would otherwise reach the reporters and the pipeline
graph with no source location. :func:`_backfill_anchor_locations` resolves
those anchors back to a document + template line once, here, instead of in
every rule (ARGO-001 / ARGO-002 already set locations natively). This
mirrors the Tekton orchestrator.
"""
from __future__ import annotations

from .._yaml_lines import line_of
from ..base import Finding, Location
from ..rule import apply_rule_metadata, discover_rules
from .base import ArgoBaseCheck, ArgoContext, ArgoDoc, iter_templates, template_name


class ArgoChecks(ArgoBaseCheck):

    def __init__(
        self, ctx: ArgoContext, target: str | None = None,
    ) -> None:
        super().__init__(ctx, target)
        self._rules = discover_rules(
            "pipeline_check.core.checks.argo.rules"
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
    finding: Finding, doc_index: dict[tuple[str, str], ArgoDoc],
) -> None:
    """Populate ``finding.locations`` from its ``job_anchors``.

    No-op when the finding already carries locations (ARGO-001 / ARGO-002)
    or has no anchors. Anchors that don't resolve are skipped.
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
    anchor: str, doc_index: dict[tuple[str, str], ArgoDoc],
) -> Location | None:
    """Resolve a ``<Kind>/<name>:<template>`` anchor to a :class:`Location`."""
    head, sep, tmpl = anchor.partition(":")
    kind, slash, name = head.partition("/")
    if not slash:
        return None
    doc = doc_index.get((kind, name))
    if doc is None:
        return None
    line: int | None = None
    if sep and tmpl:
        for idx, t in enumerate(iter_templates(doc)):
            if template_name(t, idx) == tmpl:
                line = line_of(t)
                break
    if line is None:
        line = line_of(doc.data)
    return Location(
        path=doc.path, start_line=line, end_line=line,
        doc_index=doc.doc_index,
    )
