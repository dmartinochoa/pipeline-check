"""Tekton orchestrator. Auto-discovers TKN-* rules under ``rules/``.

Each rule receives the full :class:`TektonContext` and emits a single
aggregated Finding spanning every doc it cares about. This mirrors
the Kubernetes orchestrator's shape. Tekton manifests live in
multi-doc YAML, and the per-doc / per-kind branching belongs inside
the rule, not in the orchestrator.
"""
from __future__ import annotations

from ..base import Finding
from ..rule import discover_rules
from .base import TektonBaseCheck, TektonContext


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
        for rule, check_fn in self._rules:
            finding = check_fn(self.ctx)
            finding.cwe = list(rule.cwe)
            finding.incident_refs = list(rule.incident_refs)
            findings.append(finding)
        return findings
