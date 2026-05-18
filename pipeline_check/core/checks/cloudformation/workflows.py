"""CloudFormation rule orchestrator.

Mirror of :class:`pipeline_check.core.checks.terraform.workflows.TerraformRuleChecks`.
Auto-discovers every module under ``cloudformation/rules/`` and runs the
``RULE`` / ``check(ctx)`` pair as a single ``BaseCheck``-shaped unit.

The legacy per-service classes (``CodeBuildChecks``, ``IAMChecks``, …)
still exist for the per-service unit tests under
``tests/cloudformation/`` — both paths delegate to the same helper
functions so they can't drift apart in semantics.
"""
from __future__ import annotations

from ..base import Finding
from ..rule import discover_rules
from .base import CloudFormationBaseCheck, CloudFormationContext


class CloudFormationRuleChecks(CloudFormationBaseCheck):
    """Runs every rule under ``pipeline_check.core.checks.cloudformation.rules``."""

    def __init__(
        self, ctx: CloudFormationContext, target: str | None = None,
    ) -> None:
        super().__init__(ctx, target)
        self._rules = discover_rules(
            "pipeline_check.core.checks.cloudformation.rules"
        )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for rule, check_fn in self._rules:
            batch = check_fn(self.ctx) or []
            for finding in batch:
                if not finding.cwe:
                    finding.cwe = list(rule.cwe)
                if not finding.incident_refs:
                    finding.incident_refs = list(rule.incident_refs)
                if finding.exploit_example is None:
                    finding.exploit_example = rule.exploit_example
            findings.extend(batch)
        return findings


__all__ = ["CloudFormationRuleChecks"]
