"""OCI manifest orchestrator.

Each ``OCI-*`` rule lives in its own module under ``rules/``. This
orchestrator auto-discovers them and runs each against every loaded
manifest.
"""
from __future__ import annotations

from ..base import Finding
from ..rule import discover_rules
from .base import OCIBaseCheck, OCIContext


class OCIManifestChecks(OCIBaseCheck):

    def __init__(
        self, ctx: OCIContext, target: str | None = None,
    ) -> None:
        super().__init__(ctx, target)
        self._rules = discover_rules(
            "pipeline_check.core.checks.oci.rules"
        )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for manifest in self.ctx.manifests:
            for rule, check_fn in self._rules:
                finding = check_fn(manifest)
                finding.cwe = list(rule.cwe)
                if not finding.incident_refs:
                    finding.incident_refs = list(rule.incident_refs)
                if finding.exploit_example is None:
                    finding.exploit_example = rule.exploit_example
                findings.append(finding)
        return findings
