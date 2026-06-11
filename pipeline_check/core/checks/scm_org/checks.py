"""GitHub org-governance orchestrator.

Auto-discovers the ``ORG-*`` rule modules under ``rules/`` and runs each
over the loaded org context. Each rule's ``check`` takes the
:class:`SCMOrgContext` and returns a finding (or a list of them), so the
single org fetch fans out to one finding per org-level control.
"""
from __future__ import annotations

from ..base import Finding
from ..rule import apply_rule_metadata, as_finding_list, discover_rules
from .base import SCMOrgBaseCheck, SCMOrgContext


class SCMOrgChecks(SCMOrgBaseCheck):

    def __init__(
        self, ctx: SCMOrgContext, target: str | None = None,
    ) -> None:
        super().__init__(ctx, target)
        self._rules = discover_rules(
            "pipeline_check.core.checks.scm_org.rules"
        )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for rule, check_fn in self._rules:
            for finding in as_finding_list(check_fn(self.ctx)):
                apply_rule_metadata(finding, rule)
                findings.append(finding)
        return findings
