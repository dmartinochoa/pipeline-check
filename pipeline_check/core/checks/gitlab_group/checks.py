"""GitLab group-governance orchestrator.

Auto-discovers the ``GLGRP-*`` rule modules under ``rules/`` and runs each
over the loaded group context. Each rule's ``check`` takes the
:class:`GitLabGroupContext` and returns a finding, so the single group
fetch fans out to one finding per group-level control. Mirrors
:class:`SCMOrgChecks` for GitHub.
"""
from __future__ import annotations

from ..base import Finding
from ..rule import apply_rule_metadata, as_finding_list, discover_rules
from .base import GitLabGroupBaseCheck, GitLabGroupContext


class GitLabGroupChecks(GitLabGroupBaseCheck):

    def __init__(
        self, ctx: GitLabGroupContext, target: str | None = None,
    ) -> None:
        super().__init__(ctx, target)
        self._rules = discover_rules(
            "pipeline_check.core.checks.gitlab_group.rules"
        )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for rule, check_fn in self._rules:
            for finding in as_finding_list(check_fn(self.ctx)):
                apply_rule_metadata(finding, rule)
                findings.append(finding)
        return findings
