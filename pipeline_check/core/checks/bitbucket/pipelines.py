"""Bitbucket Pipelines orchestrator.

Individual BB-* checks each live in their own module under
``pipeline_check/core/checks/bitbucket/rules/``. This module is a
thin driver — ``discover_rules`` auto-imports every rule at
construction time and the orchestrator runs each against every
loaded pipeline document.

Adding a check is a one-file change — drop ``bbNNN_<name>.py`` into
``rules/`` exporting ``RULE`` and ``check``. The orchestrator, the
test fixtures catalogue, and the provider reference doc all pick it
up automatically.
"""
from __future__ import annotations

from ..base import Finding
from ..rule import discover_rules
from .base import BitbucketBaseCheck


class BitbucketPipelineChecks(BitbucketBaseCheck):
    """Runs every rule under
    ``pipeline_check.core.checks.bitbucket.rules`` on every loaded
    pipeline document."""

    def __init__(self, ctx, target=None) -> None:
        super().__init__(ctx, target)
        # Discovery happens once per orchestrator. The rules registry
        # is a list of ``(Rule, check_fn)`` pairs in lexical module
        # order, which matches the natural BB-001 → BB-010 sort.
        self._rules = discover_rules("pipeline_check.core.checks.bitbucket.rules")

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for p in self.ctx.pipelines:
            for rule, check_fn in self._rules:
                finding = check_fn(p.path, p.data)
                finding.cwe = list(rule.cwe)
                findings.append(finding)
        return findings
