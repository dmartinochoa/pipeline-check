"""Maven orchestrator.

Each ``MVN-*`` rule lives in its own module under ``rules/``. This
orchestrator auto-discovers them and runs each against every loaded
``pom.xml`` / ``settings.xml``.
"""
from __future__ import annotations

from ..base import Finding
from ..rule import apply_rule_metadata, discover_rules, wants_ctx_kwarg
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
        # Rules that need cross-file state (MVN-008's publish-time
        # table populated by --resolve-remote) declare a second
        # positional parameter; pass the context for those. One-arg
        # rules are unaffected.
        rule_pass_ctx = {
            id(check_fn): wants_ctx_kwarg(check_fn)
            for _, check_fn in self._rules
        }
        for pom in self.ctx.files:
            for rule, check_fn in self._rules:
                if rule_pass_ctx[id(check_fn)]:
                    finding = check_fn(pom, self.ctx)
                else:
                    finding = check_fn(pom)
                apply_rule_metadata(finding, rule)
                findings.append(finding)
        return findings
