"""Kubernetes manifest orchestrator.

Each K8S-* rule lives in its own module under ``rules/``. This
orchestrator auto-discovers them and runs each against every parsed
manifest. Rules that only apply to specific kinds (e.g. K8S-018
applies only to ``Kind: Secret``) short-circuit with ``passed=True``
when the manifest doesn't match.
"""
from __future__ import annotations

from ..base import Finding
from ..rule import discover_rules
from .base import KubernetesBaseCheck, KubernetesContext


class KubernetesManifestChecks(KubernetesBaseCheck):

    def __init__(
        self, ctx: KubernetesContext, target: str | None = None,
    ) -> None:
        super().__init__(ctx, target)
        self._rules = discover_rules(
            "pipeline_check.core.checks.kubernetes.rules"
        )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        # Strategy: each rule sees the full context. Rules that emit
        # one Finding per offender across all manifests (e.g. K8S-001
        # walks every container) keep the report compact; rules that
        # are kind-scoped (K8S-018) likewise emit one summary Finding.
        for rule, check_fn in self._rules:
            finding = check_fn(self.ctx)
            finding.cwe = list(rule.cwe)
            if not finding.incident_refs:
                finding.incident_refs = list(rule.incident_refs)
            if finding.exploit_example is None:
                finding.exploit_example = rule.exploit_example
            findings.append(finding)
        return findings
