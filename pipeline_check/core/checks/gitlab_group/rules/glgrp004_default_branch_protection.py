"""GLGRP-004. The group's default branch protection is disabled for new projects."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import GitLabGroupContext, group_resource

RULE = Rule(
    id="GLGRP-004",
    title="GitLab group default branch protection is disabled for new projects",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-1",),
    cwe=("CWE-284",),
    recommendation=(
        "Raise the group's ``Default branch protection`` above ``Not "
        "protected`` (Group Settings -> General -> Permissions and group "
        "features). At ``0`` (Not protected), every new project created in "
        "the group starts with a default branch any Developer can push to "
        "directly, force-push, and delete, with no review gate, so a single "
        "compromised or careless member can rewrite history or ship "
        "unreviewed code on day one. Set it to at least ``Partially "
        "protected`` (no force-push) and prefer ``Fully protected`` so new "
        "projects inherit a safe default; individual projects can still "
        "tighten it further. The repo-level analog is SCM-001."
    ),
    docs_note=(
        "Reads ``default_branch_protection`` from ``GET /groups/{group}`` "
        "and fires when it is ``0`` (Not protected). ``1``-``4`` (partial / "
        "full / protected-against-push / full-after-initial-push) pass. "
        "GitLab is migrating this integer to a "
        "``default_branch_protection_defaults`` object; when only that newer "
        "form is returned (the integer absent) the rule passes with an "
        "'unavailable' note rather than guessing at the object's shape, so "
        "it never produces a false finding. This is the group-wide default "
        "for new projects; SCM-001 audits a specific repository's branch "
        "protection."
    ),
)


def check(ctx: GitLabGroupContext) -> Finding:
    meta = ctx.group_meta
    if not isinstance(meta, dict):
        return RULE.pass_finding(
            group_resource(ctx),
            "Group settings were not available (see warnings); the default "
            "branch-protection level could not be read.",
        )
    level = meta.get("default_branch_protection")
    if not isinstance(level, int) or isinstance(level, bool):
        return RULE.pass_finding(
            group_resource(ctx),
            "The group does not expose a ``default_branch_protection`` "
            "integer (newer GitLab returns a "
            "``default_branch_protection_defaults`` object, not interpreted "
            "here); not evaluated.",
        )
    if level >= 1:
        return RULE.pass_finding(
            group_resource(ctx),
            f"Group ``{ctx.group}`` sets a default branch-protection level "
            f"of {level} for new projects.",
        )
    return RULE.fail_finding(
        group_resource(ctx),
        f"Group ``{ctx.group}`` leaves new projects' default branch "
        "unprotected (``default_branch_protection`` = 0): any Developer can "
        "push directly, force-push, or delete the default branch with no "
        "review gate. Raise the group default to at least partially "
        "protected.",
    )
