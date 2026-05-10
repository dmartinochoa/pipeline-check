"""Argo Workflows orchestrator. Auto-discovers ARGO-* rules.

Each rule receives the full :class:`ArgoContext` and emits a single
aggregated Finding. Mirrors the Tekton / Kubernetes orchestrator
shape so rules that span multiple docs can correlate without the
orchestrator needing to know which is which.
"""
from __future__ import annotations

from ..base import Finding
from ..rule import discover_rules
from .base import ArgoBaseCheck, ArgoContext


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
        for rule, check_fn in self._rules:
            finding = check_fn(self.ctx)
            finding.cwe = list(rule.cwe)
            if not finding.incident_refs:
                finding.incident_refs = list(rule.incident_refs)
            if finding.exploit_example is None:
                finding.exploit_example = rule.exploit_example
            findings.append(finding)
        return findings
