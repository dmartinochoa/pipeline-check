"""Run-forensics orchestrator.

Auto-discovers the ``RUN-*`` rule modules under ``rules/`` and runs each
over the loaded run history. Each rule's ``check`` takes the
:class:`RunsContext` and returns a list of findings (one per offending
run, or a single passing finding when the run history is clean), so a
rule can fan a single API pull out to per-run findings.
"""
from __future__ import annotations

from ..base import Finding
from ..rule import apply_rule_metadata, as_finding_list, discover_rules
from .base import RunsBaseCheck, RunsContext


class RunsChecks(RunsBaseCheck):

    def __init__(self, ctx: RunsContext, target: str | None = None) -> None:
        super().__init__(ctx, target)
        self._rules = discover_rules("pipeline_check.core.checks.runs.rules")

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for rule, check_fn in self._rules:
            for finding in as_finding_list(check_fn(self.ctx)):
                apply_rule_metadata(finding, rule)
                findings.append(finding)
        return findings
