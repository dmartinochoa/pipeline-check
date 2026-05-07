"""GitHub Actions workflow orchestrator.

Individual GHA-* checks each live in their own module under
``pipeline_check/core/checks/github/rules/``. This module is a thin
driver — ``discover_rules`` auto-imports every rule at construction
time and the orchestrator runs each against every loaded workflow
document.

Adding a check is a one-file change — drop ``ghaNNN_<name>.py`` into
``rules/`` exporting ``RULE`` and ``check``. The orchestrator, the
test fixtures catalog, and the provider reference doc all pick it
up automatically.

Rule signature: ``check(path: str, doc: dict) -> Finding`` is the
default. Rules that need the caller-vs-callee context for resolved
reusable workflows extend the signature to
``check(path: str, doc: dict, wf: Workflow) -> Finding``; the
orchestrator detects the third parameter at discovery time via
``inspect.signature`` and dispatches accordingly. Existing rules
don't need to change.
"""
from __future__ import annotations

import inspect
from collections.abc import Callable
from typing import Any

from ..base import Finding
from ..rule import Rule, discover_rules
from .base import GitHubBaseCheck, GitHubContext


def _accepts_workflow(check_fn: Callable[..., Finding]) -> bool:
    """True iff *check_fn* declares a third positional parameter.

    Rule modules can opt into receiving the full :class:`Workflow`
    dataclass (which carries resolver-provided inheritance metadata)
    by widening their signature to three positionals. This helper
    inspects the signature once at orchestrator construction so the
    per-call dispatch is a flag check, not a re-introspection.
    """
    try:
        sig = inspect.signature(check_fn)
    except (TypeError, ValueError):
        return False
    positionals = [
        p for p in sig.parameters.values()
        if p.kind in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
    ]
    return len(positionals) >= 3


class WorkflowChecks(GitHubBaseCheck):
    """Runs every rule under
    ``pipeline_check.core.checks.github.rules`` on every loaded
    workflow document."""

    def __init__(
        self, ctx: GitHubContext, target: str | None = None,
    ) -> None:
        super().__init__(ctx, target)
        # Discovery happens once per orchestrator. The rules registry
        # is a list of ``(Rule, check_fn)`` pairs in lexical module
        # order, which matches the natural GHA-001 → GHA-012 sort.
        rules = discover_rules("pipeline_check.core.checks.github.rules")
        self._rules: list[tuple[Rule, Callable[..., Finding], bool]] = [
            (rule, fn, _accepts_workflow(fn))
            for rule, fn in rules
        ]

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for wf in self.ctx.workflows:
            for rule, check_fn, wants_wf in self._rules:
                if wants_wf:
                    finding = check_fn(wf.path, wf.data, wf)
                else:
                    finding = check_fn(wf.path, wf.data)
                finding.cwe = list(rule.cwe)
                findings.append(finding)
        return findings
