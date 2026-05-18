"""Maven orchestrator.

Each ``MVN-*`` rule lives in its own module under ``rules/``. This
orchestrator auto-discovers them and runs each against every loaded
``pom.xml`` / ``settings.xml``.
"""
from __future__ import annotations

from ..base import Finding
from ..rule import discover_rules
from .base import MavenBaseCheck, MavenContext


class MavenChecks(MavenBaseCheck):

    def __init__(
        self, ctx: MavenContext, target: str | None = None,
    ) -> None:
        super().__init__(ctx, target)
        self._rules = discover_rules(
            "pipeline_check.core.checks.maven.rules"
        )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for pom in self.ctx.files:
            for rule, check_fn in self._rules:
                finding = check_fn(pom)
                finding.cwe = list(rule.cwe)
                if not finding.incident_refs:
                    finding.incident_refs = list(rule.incident_refs)
                if finding.exploit_example is None:
                    finding.exploit_example = rule.exploit_example
                findings.append(finding)
        return findings
