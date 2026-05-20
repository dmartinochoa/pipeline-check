"""Drone pipeline orchestrator.

Each ``DR-*`` rule lives in its own module under ``rules/``. This
orchestrator auto-discovers them and runs each against every
loaded pipeline document.
"""
from __future__ import annotations

from ..base import Finding
from ..rule import apply_rule_metadata, discover_rules
from .base import DroneBaseCheck, DroneContext


class DronePipelineChecks(DroneBaseCheck):

    def __init__(
        self, ctx: DroneContext, target: str | None = None,
    ) -> None:
        super().__init__(ctx, target)
        self._rules = discover_rules(
            "pipeline_check.core.checks.drone.rules"
        )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for pipeline in self.ctx.pipelines:
            for rule, check_fn in self._rules:
                finding = check_fn(pipeline)
                apply_rule_metadata(finding, rule)
                findings.append(finding)
        return findings
