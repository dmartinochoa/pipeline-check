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

from typing import cast

from ..base import Finding
from ..rule import apply_rule_metadata, discover_rules
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
            # ``discover_rules`` types each callable's return as a
            # single ``Finding`` (the github-style signature), but the
            # AWS / TF / CF rule shape returns ``list[Finding]``. Cast
            # at the call site so mypy understands the batch is iterable.
            batch = cast("list[Finding]", check_fn(self.ctx) or [])
            for finding in batch:
                apply_rule_metadata(finding, rule)
            findings.extend(batch)
        return findings


__all__ = ["CloudFormationRuleChecks"]
