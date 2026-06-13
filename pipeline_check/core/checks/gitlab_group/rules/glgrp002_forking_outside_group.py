"""GLGRP-002. The GitLab group allows forking its projects outside the group."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import GitLabGroupContext, group_resource

RULE = Rule(
    id="GLGRP-002",
    title="GitLab group allows forking projects outside the group",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-200",),
    recommendation=(
        "Turn on ``Prevent project forking outside current group`` (Group "
        "Settings -> General -> Permissions and group features). When it is "
        "off, any member can fork a private or internal project to a "
        "namespace outside the group, where the group's branch protection, "
        "approval rules, and member 2FA policy no longer apply, and the copy "
        "persists after the member leaves. That moves source code outside "
        "the controls that govern the group, a data-exfiltration and IP-leak "
        "path that needs no exploit. The GitHub-org analog is ORG-007."
    ),
    docs_note=(
        "Reads ``prevent_forking_outside_group`` from ``GET /groups/{group}`` "
        "and fires when it is ``false``. ``true`` passes. The field is a "
        "Premium / Ultimate group setting; on a plan or token that does not "
        "return it the rule passes with an 'unavailable' note rather than "
        "guessing, so a low-scope token or free-tier group never produces a "
        "false finding."
    ),
)


def check(ctx: GitLabGroupContext) -> Finding:
    meta = ctx.group_meta
    if not isinstance(meta, dict):
        return RULE.pass_finding(
            group_resource(ctx),
            "Group settings were not available (see warnings); the "
            "project-forking policy could not be read.",
        )
    if "prevent_forking_outside_group" not in meta:
        return RULE.pass_finding(
            group_resource(ctx),
            "The token / plan does not expose the group's "
            "prevent-forking-outside-group policy (a Premium setting); not "
            "evaluated.",
        )
    if meta.get("prevent_forking_outside_group") is True:
        return RULE.pass_finding(
            group_resource(ctx),
            f"Group ``{ctx.group}`` prevents forking its projects outside the "
            "group.",
        )
    return RULE.fail_finding(
        group_resource(ctx),
        f"Group ``{ctx.group}`` allows forking its projects outside the "
        "group: any member can fork private or internal source to a personal "
        "namespace, outside the group's branch protection, approval rules, "
        "and 2FA policy.",
    )
