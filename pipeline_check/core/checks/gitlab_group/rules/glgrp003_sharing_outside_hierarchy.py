"""GLGRP-003. The group allows sharing its projects with groups outside the hierarchy."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import GitLabGroupContext, group_resource

RULE = Rule(
    id="GLGRP-003",
    title="GitLab group allows sharing projects outside the group hierarchy",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-284",),
    recommendation=(
        "Turn on ``Prevent members from sharing projects in this group with "
        "groups outside the hierarchy`` (Group Settings -> General -> "
        "Permissions and group features). When it is off, a "
        "member can share a private or internal project with a group outside "
        "the current hierarchy, granting that external group's members "
        "standing access to the project, outside the controls (branch "
        "protection, approval rules, 2FA policy, audit log) that govern this "
        "group. Restrict sharing to the hierarchy and grant external access "
        "only through reviewed, time-bound membership. The GitHub-org "
        "analog is ORG-007 (forking) / outside-collaborator policy."
    ),
    docs_note=(
        "Reads ``prevent_sharing_groups_outside_hierarchy`` from "
        "``GET /groups/{group}`` and fires when it is ``false`` (sharing "
        "outside the hierarchy is allowed). ``true`` passes. The setting is "
        "tied to Premium / SAML group features; on a plan or token that does "
        "not return it the rule passes with an 'unavailable' note rather "
        "than guessing, so a low-scope token or free-tier group never "
        "produces a false finding. Sits alongside GLGRP-002 (forking outside "
        "the group): both are group-level access-boundary controls."
    ),
)


def check(ctx: GitLabGroupContext) -> Finding:
    meta = ctx.group_meta
    if not isinstance(meta, dict):
        return RULE.pass_finding(
            group_resource(ctx),
            "Group settings were not available (see warnings); the "
            "share-outside-hierarchy policy could not be read.",
        )
    if "prevent_sharing_groups_outside_hierarchy" not in meta:
        return RULE.pass_finding(
            group_resource(ctx),
            "The token / plan does not expose the group's "
            "prevent-sharing-outside-hierarchy policy (a Premium / SAML "
            "setting); not evaluated.",
        )
    if meta.get("prevent_sharing_groups_outside_hierarchy") is True:
        return RULE.pass_finding(
            group_resource(ctx),
            f"Group ``{ctx.group}`` prevents sharing its projects with "
            "groups outside the hierarchy.",
        )
    return RULE.fail_finding(
        group_resource(ctx),
        f"Group ``{ctx.group}`` allows sharing its projects with groups "
        "outside the hierarchy: a member can grant an external group "
        "standing access to a private or internal project, outside this "
        "group's branch protection, approval rules, and 2FA policy.",
    )
