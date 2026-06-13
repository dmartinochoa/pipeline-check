"""GitLab run-forensics orchestrator.

Auto-discovers the ``GLRUN-*`` rule modules under ``rules/`` and runs each
over the loaded pipeline history. Each rule's ``check`` takes the
:class:`GitLabRunsContext` and returns a list of findings (one per
offending pipeline, or a single passing finding when the history is
clean), so a rule can fan a single API pull out to per-pipeline findings.
"""
from __future__ import annotations

from ..base import Finding
from ..rule import apply_rule_metadata, as_finding_list, discover_rules
from .base import GitLabRunsBaseCheck, GitLabRunsContext


class GitLabRunsChecks(GitLabRunsBaseCheck):

    def __init__(
        self, ctx: GitLabRunsContext, target: str | None = None,
    ) -> None:
        super().__init__(ctx, target)
        self._rules = discover_rules(
            "pipeline_check.core.checks.gitlab_runs.rules"
        )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for rule, check_fn in self._rules:
            for finding in as_finding_list(check_fn(self.ctx)):
                apply_rule_metadata(finding, rule)
                findings.append(finding)
        return findings
