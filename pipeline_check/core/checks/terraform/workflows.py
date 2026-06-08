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

from ..base import Confidence, Finding
from ..rule import apply_rule_metadata, as_finding_list, discover_rules
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
            # ``discover_rules`` types each callable's return as a single
            # ``Finding`` (the github-style signature), but the AWS / TF /
            # CF rule shape returns ``list[Finding]``. ``as_finding_list``
            # normalizes both that and the lone ``Finding`` that
            # ``_guard_check`` emits when a rule crashes, so one bad rule
            # degrades to one finding instead of dropping the provider.
            batch = as_finding_list(check_fn(self.ctx))
            for finding in batch:
                # Backfill metadata the rule carries but the helper
                # function may not have populated (CWE, incident refs,
                # exploit example). Keeps the dual-path execution
                # model consistent: the legacy service classes also
                # emit these as zero-values, the orchestrator
                # canonicalizes them from the Rule.
                apply_rule_metadata(finding, rule)
            findings.extend(batch)

        if (
            self.ctx.source_mode == "hcl"
            and self.ctx._resources_with_unresolved
        ):
            _demote = {
                Confidence.HIGH: Confidence.MEDIUM,
                Confidence.MEDIUM: Confidence.LOW,
            }
            for f in findings:
                if (
                    not f.passed
                    and not f.confidence_locked
                    and f.resource in self.ctx._resources_with_unresolved
                ):
                    if f.confidence in _demote:
                        f.confidence = _demote[f.confidence]

        return findings


__all__ = ["TerraformRuleChecks"]
