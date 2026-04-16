"""GitHub Actions workflow orchestrator.

Individual GHA-* checks each live in their own module under
``pipeline_check/core/checks/github/rules/``. This module is a thin
driver — ``discover_rules`` auto-imports every rule at construction
time and the orchestrator runs each against every loaded workflow
document.

Adding a check is a one-file change — drop ``ghaNNN_<name>.py`` into
``rules/`` exporting ``RULE`` and ``check``. The orchestrator, the
test fixtures catalogue, and the provider reference doc all pick it
up automatically.
"""
from __future__ import annotations

from ..base import Finding
from ..rule import discover_rules
from .base import GitHubBaseCheck


class WorkflowChecks(GitHubBaseCheck):
    """Runs every rule under
    ``pipeline_check.core.checks.github.rules`` on every loaded
    workflow document."""

    def __init__(self, ctx, target=None) -> None:
        super().__init__(ctx, target)
        # Discovery happens once per orchestrator. The rules registry
        # is a list of ``(Rule, check_fn)`` pairs in lexical module
        # order, which matches the natural GHA-001 → GHA-012 sort.
        self._rules = discover_rules("pipeline_check.core.checks.github.rules")

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for wf in self.ctx.workflows:
            for rule, check_fn in self._rules:
                finding = check_fn(wf.path, wf.data)
                finding.cwe = list(rule.cwe)
                findings.append(finding)
        return findings
