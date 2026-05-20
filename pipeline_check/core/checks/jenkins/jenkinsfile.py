"""Jenkins pipeline orchestrator.

Individual JF-* checks each live in their own module under
``pipeline_check/core/checks/jenkins/rules/``. Jenkins rules take a
single ``Jenkinsfile`` object (carrying ``.path``, ``.text``,
``.library_refs``, ``.stages``) rather than the ``(path, doc)`` pair
the YAML providers use. Groovy isn't parsable as a dict, so the
orchestrator hands the whole parsed blob to each rule.

Adding a check is a one-file change, drop ``jfNNN_<name>.py`` into
``rules/`` exporting ``RULE`` and ``check``. The orchestrator, the
test fixtures catalog, and the provider reference doc all pick it
up automatically.
"""
from __future__ import annotations

from ..base import Finding
from ..rule import apply_rule_metadata, discover_rules
from .base import JenkinsBaseCheck, JenkinsContext


class JenkinsfileChecks(JenkinsBaseCheck):
    """Runs every rule under
    ``pipeline_check.core.checks.jenkins.rules`` on every loaded
    Jenkinsfile."""

    def __init__(
        self, ctx: JenkinsContext, target: str | None = None,
    ) -> None:
        super().__init__(ctx, target)
        # Discovery happens once per orchestrator. The rules registry
        # is a list of ``(Rule, check_fn)`` pairs in lexical module
        # order, which matches the natural JF-001 → JF-013 sort.
        self._rules = discover_rules("pipeline_check.core.checks.jenkins.rules")

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for jf in self.ctx.files:
            for rule, check_fn in self._rules:
                finding = check_fn(jf)
                apply_rule_metadata(finding, rule)
                findings.append(finding)
        return findings
