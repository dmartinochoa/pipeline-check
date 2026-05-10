"""Dockerfile orchestrator.

Each DF-* rule lives in its own module under ``rules/``. This
orchestrator auto-discovers them and runs each against every
loaded Dockerfile.
"""
from __future__ import annotations

from ..base import Finding
from ..rule import discover_rules
from .base import DockerfileBaseCheck, DockerfileContext


class DockerfileChecks(DockerfileBaseCheck):

    def __init__(
        self, ctx: DockerfileContext, target: str | None = None,
    ) -> None:
        super().__init__(ctx, target)
        self._rules = discover_rules(
            "pipeline_check.core.checks.dockerfile.rules"
        )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for df in self.ctx.dockerfiles:
            for rule, check_fn in self._rules:
                finding = check_fn(df)
                finding.cwe = list(rule.cwe)
                if not finding.incident_refs:
                    finding.incident_refs = list(rule.incident_refs)
                findings.append(finding)
        return findings
