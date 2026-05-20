"""GitHub Actions workflow orchestrator.

Individual GHA-* checks each live in their own module under
``pipeline_check/core/checks/github/rules/``. This module is a thin
driver, ``discover_rules`` auto-imports every rule at construction
time and the orchestrator runs each against every loaded workflow
document.

Adding a check is a one-file change, drop ``ghaNNN_<name>.py`` into
``rules/`` exporting ``RULE`` and ``check``. The orchestrator, the
test fixtures catalog, and the provider reference doc all pick it
up automatically.

Rule signature: ``check(path: str, doc: dict) -> Finding`` is the
default. Rules that need the caller-vs-callee context for resolved
reusable workflows extend the signature to
``check(path: str, doc: dict, wf: Workflow) -> Finding``. Rules that
need cross-workflow analysis (e.g., looking up the callee body of a
reusable-workflow ``uses:`` reference to confirm the input is
actually consumed in a sink) widen further to
``check(path, doc, wf, ctx: GitHubContext) -> Finding``. The
orchestrator detects each form at discovery time via
``inspect.signature`` and dispatches accordingly. Existing rules
don't need to change.
"""
from __future__ import annotations

import inspect
from collections.abc import Callable

from ..base import Finding
from ..rule import Rule, apply_rule_metadata, discover_rules
from .base import GitHubBaseCheck, GitHubContext


def _positional_count(check_fn: Callable[..., Finding]) -> int:
    """Return the count of positional parameters on *check_fn*.

    Used by the orchestrator to dispatch:

      * 2 positionals -> ``check(path, doc)``;
      * 3 positionals -> ``check(path, doc, wf)``;
      * 4 positionals -> ``check(path, doc, wf, ctx)``.

    Anything outside [2, 4] falls through to the default 2-arg
    invocation; rules whose signature can't be introspected
    (lambdas, C-implemented callables) get the same treatment.
    """
    try:
        sig = inspect.signature(check_fn)
    except (TypeError, ValueError):
        return 2
    positionals = [
        p for p in sig.parameters.values()
        if p.kind in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
    ]
    return len(positionals)


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
        self._rules: list[tuple[Rule, Callable[..., Finding], int]] = [
            (rule, fn, _positional_count(fn))
            for rule, fn in rules
        ]

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for wf in self.ctx.workflows:
            for rule, check_fn, argc in self._rules:
                if argc >= 4:
                    finding = check_fn(wf.path, wf.data, wf, self.ctx)
                elif argc == 3:
                    finding = check_fn(wf.path, wf.data, wf)
                else:
                    finding = check_fn(wf.path, wf.data)
                apply_rule_metadata(finding, rule)
                findings.append(finding)
        return findings
