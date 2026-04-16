"""CircleCI config orchestrator.

Individual CC-* checks each live in their own module under
``pipeline_check/core/checks/circleci/rules/``. This module is a
thin driver — ``discover_rules`` auto-imports every rule at
construction time and the orchestrator runs each against every
loaded config document.

Adding a check is a one-file change — drop ``ccNNN_<name>.py`` into
``rules/`` exporting ``RULE`` and ``check``. The orchestrator, the
test fixtures catalogue, and the provider reference doc all pick it
up automatically.
"""
from __future__ import annotations

from ..base import Finding
from ..rule import discover_rules
from .base import CircleCIBaseCheck


class CircleCIPipelineChecks(CircleCIBaseCheck):
    """Runs every rule under
    ``pipeline_check.core.checks.circleci.rules`` on every loaded
    config document."""

    def __init__(self, ctx, target=None) -> None:
        super().__init__(ctx, target)
        self._rules = discover_rules("pipeline_check.core.checks.circleci.rules")

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for p in self.ctx.pipelines:
            for rule, check_fn in self._rules:
                finding = check_fn(p.path, p.data)
                finding.cwe = list(rule.cwe)
                findings.append(finding)
        return findings
