"""Developer-environment orchestrator.

Each DEV-* rule lives in its own module under ``rules/``. This
orchestrator auto-discovers them and runs each against every loaded
config document. Rules receive the whole :class:`WorkspaceFile` (not
just the parsed dict) so they can dispatch on ``kind`` and fall back
to the raw text for line anchoring.
"""
from __future__ import annotations

from ..base import Finding
from ..rule import apply_rule_metadata, discover_rules
from .base import DevEnvBaseCheck, DevEnvContext


class DevEnvChecks(DevEnvBaseCheck):

    def __init__(self, ctx: DevEnvContext, target: str | None = None) -> None:
        super().__init__(ctx, target)
        self._rules = discover_rules("pipeline_check.core.checks.devenv.rules")

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for wf in self.ctx.files:
            for rule, check_fn in self._rules:
                finding = check_fn(wf.path, wf)
                apply_rule_metadata(finding, rule)
                findings.append(finding)
        return findings
