"""Cloud Build pipeline orchestrator.

Each GCB-* rule lives in its own module under ``rules/``. This
orchestrator auto-discovers them and runs each against every loaded
Cloud Build document.
"""
from __future__ import annotations

from ..base import Finding
from ..rule import discover_rules
from .base import CloudBuildBaseCheck


class CloudBuildPipelineChecks(CloudBuildBaseCheck):

    def __init__(self, ctx, target=None) -> None:
        super().__init__(ctx, target)
        self._rules = discover_rules(
            "pipeline_check.core.checks.cloudbuild.rules"
        )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for p in self.ctx.pipelines:
            for rule, check_fn in self._rules:
                finding = check_fn(p.path, p.data)
                finding.cwe = list(rule.cwe)
                findings.append(finding)
        return findings
