"""Modelfile orchestrator.

Auto-discovers the ``MODEL-*`` rule modules under ``rules/`` and runs each
over the loaded Modelfiles. Each rule's ``check`` takes the
:class:`ModelfileContext` and returns a list of findings (one per parsed
Modelfile), so a single rule fans out across every Modelfile in the scan.
"""
from __future__ import annotations

from ..base import Finding
from ..rule import apply_rule_metadata, as_finding_list, discover_rules
from .base import ModelfileBaseCheck, ModelfileContext


class ModelfileChecks(ModelfileBaseCheck):

    def __init__(self, ctx: ModelfileContext, target: str | None = None) -> None:
        super().__init__(ctx, target)
        self._rules = discover_rules("pipeline_check.core.checks.modelfile.rules")

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for rule, check_fn in self._rules:
            for finding in as_finding_list(check_fn(self.ctx)):
                apply_rule_metadata(finding, rule)
                findings.append(finding)
        return findings
