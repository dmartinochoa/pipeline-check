"""Maven orchestrator.

Each ``MVN-*`` rule lives in its own module under ``rules/``. This
orchestrator auto-discovers them and runs each against every loaded
``pom.xml`` / ``settings.xml``.
"""
from __future__ import annotations

import inspect
from collections.abc import Callable

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
        # Rules that need cross-file state (MVN-008's publish-time
        # table populated by --resolve-remote) declare a second
        # positional parameter; pass the context for those. One-arg
        # rules are unaffected.
        rule_pass_ctx = {
            id(check_fn): _wants_ctx_kwarg(check_fn)
            for _, check_fn in self._rules
        }
        for pom in self.ctx.files:
            for rule, check_fn in self._rules:
                if rule_pass_ctx[id(check_fn)]:
                    finding = check_fn(pom, self.ctx)
                else:
                    finding = check_fn(pom)
                finding.cwe = list(rule.cwe)
                if not finding.incident_refs:
                    finding.incident_refs = list(rule.incident_refs)
                if finding.exploit_example is None:
                    finding.exploit_example = rule.exploit_example
                findings.append(finding)
        return findings


def _wants_ctx_kwarg(check_fn: Callable[..., Finding]) -> bool:
    """Return True if *check_fn* declares a second positional
    parameter (typically annotated ``MavenContext``).

    Mirrors the matching helper in ``pypi/pipelines.py`` and
    ``npm/pipelines.py`` so rules that need cross-file state can
    opt in without forcing every rule to take a context argument.
    """
    try:
        params = list(inspect.signature(check_fn).parameters.values())
    except (TypeError, ValueError):
        return False
    return len(params) >= 2
