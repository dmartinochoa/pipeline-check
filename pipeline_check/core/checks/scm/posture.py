"""SCM posture orchestrator.

Each ``SCM-*`` rule lives in its own module under ``rules/``. This
orchestrator auto-discovers them and runs each against every loaded
repo snapshot. Mirrors :class:`OCIManifestChecks` and the rest of
the rule-based provider orchestrators.
"""
from __future__ import annotations

from ..base import Finding
from ..rule import discover_rules
from .base import SCMBaseCheck, SCMContext


class SCMPostureChecks(SCMBaseCheck):

    def __init__(
        self, ctx: SCMContext, target: str | None = None,
    ) -> None:
        super().__init__(ctx, target)
        self._rules = discover_rules(
            "pipeline_check.core.checks.scm.rules"
        )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for snapshot in self.ctx.repos:
            for rule, check_fn in self._rules:
                finding = check_fn(snapshot)
                finding.cwe = list(rule.cwe)
                if not finding.incident_refs:
                    finding.incident_refs = list(rule.incident_refs)
                if finding.exploit_example is None:
                    finding.exploit_example = rule.exploit_example
                findings.append(finding)
        return findings
