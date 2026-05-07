"""Buildkite pipeline orchestrator.

Each BK-* rule lives in its own module under ``rules/``. This
orchestrator auto-discovers them and runs each against every loaded
Buildkite document.
"""
from __future__ import annotations

from ..base import Finding
from ..rule import discover_rules
from .base import BuildkiteBaseCheck, BuildkiteContext


class BuildkitePipelineChecks(BuildkiteBaseCheck):

    def __init__(
        self, ctx: BuildkiteContext, target: str | None = None,
    ) -> None:
        super().__init__(ctx, target)
        self._rules = discover_rules(
            "pipeline_check.core.checks.buildkite.rules"
        )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for p in self.ctx.pipelines:
            for rule, check_fn in self._rules:
                finding = check_fn(p.path, p.data)
                finding.cwe = list(rule.cwe)
                findings.append(finding)
        return findings
