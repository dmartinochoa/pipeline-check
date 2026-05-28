"""Cargo orchestrator.

Each ``CARGO-*`` rule lives in its own module under ``rules/``. This
orchestrator auto-discovers them and runs each against every loaded
``Cargo.toml``.
"""
from __future__ import annotations

from ..base import Finding
from ..rule import apply_rule_metadata, discover_rules
from .base import CargoBaseCheck, CargoContext


class CargoChecks(CargoBaseCheck):

    def __init__(
        self, ctx: CargoContext, target: str | None = None,
    ) -> None:
        super().__init__(ctx, target)
        self._rules = discover_rules(
            "pipeline_check.core.checks.cargo.rules"
        )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for pom in self.ctx.files:
            for rule, check_fn in self._rules:
                finding = check_fn(pom)
                apply_rule_metadata(finding, rule)
                findings.append(finding)
        return findings
