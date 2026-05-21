"""Argo CD orchestrator. Auto-discovers ARGOCD-* rules."""
from __future__ import annotations

from ..base import Finding
from ..rule import apply_rule_metadata, discover_rules
from .base import ArgoCDBaseCheck, ArgoCDContext


class ArgoCDChecks(ArgoCDBaseCheck):

    def __init__(
        self, ctx: ArgoCDContext, target: str | None = None,
    ) -> None:
        super().__init__(ctx, target)
        self._rules = discover_rules(
            "pipeline_check.core.checks.argocd.rules"
        )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for rule, check_fn in self._rules:
            finding = check_fn(self.ctx)
            apply_rule_metadata(finding, rule)
            findings.append(finding)
        return findings
