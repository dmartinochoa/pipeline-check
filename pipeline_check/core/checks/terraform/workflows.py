"""Terraform rule orchestrator.

Mirrors :class:`pipeline_check.core.checks.aws.workflows.AWSRuleChecks`:
auto-discovers every module under ``terraform/rules/`` and runs the
``RULE`` / ``check(ctx)`` pair as a single ``BaseCheck``-shaped unit.

The legacy per-service classes (``CodeBuildChecks``, ``IAMChecks``, …)
still exist in this package as a stable test surface, but the provider
entry point (:mod:`pipeline_check.core.providers.terraform`) routes
runtime scanning through this orchestrator so the rule metadata
(severity, OWASP, CWE, recommendation, docs_note) feeds the SARIF
output, the HTML report's rule cards, and the doc generator's chip
system from a single source of truth.
"""
from __future__ import annotations

from typing import cast

from ..base import Finding
from ..rule import discover_rules
from .base import TerraformBaseCheck, TerraformContext


class TerraformRuleChecks(TerraformBaseCheck):
    """Runs every rule under ``pipeline_check.core.checks.terraform.rules``."""

    def __init__(
        self, ctx: TerraformContext, target: str | None = None,
    ) -> None:
        super().__init__(ctx, target)
        self._rules = discover_rules(
            "pipeline_check.core.checks.terraform.rules"
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
                # Backfill metadata the rule carries but the helper
                # function may not have populated (CWE, incident refs,
                # exploit example). Keeps the dual-path execution
                # model consistent: the legacy service classes also
                # emit these as zero-values, the orchestrator
                # canonicalizes them from the Rule.
                if not finding.cwe:
                    finding.cwe = list(rule.cwe)
                if not finding.incident_refs:
                    finding.incident_refs = list(rule.incident_refs)
                if finding.exploit_example is None:
                    finding.exploit_example = rule.exploit_example
            findings.extend(batch)
        return findings


__all__ = ["TerraformRuleChecks"]
