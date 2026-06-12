"""ORG-008. Members can create public repositories under the org."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import SCMOrgContext, org_resource

RULE = Rule(
    id="ORG-008",
    title="Organization lets members create public repositories",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-200",),
    recommendation=(
        "Restrict public-repository creation to organization owners (Org "
        "Settings -> Member privileges -> Repository creation: allow members "
        "to create only ``Private`` repositories, or no repositories). When "
        "any member can create a ``Public`` repository, one push of internal "
        "code to a member-created public repo exposes source, secrets, or "
        "customer data to the whole internet, with no review and no admin in "
        "the loop. Owners can still create public repos for genuine "
        "open-source work, and members get private repos for everything else."
    ),
    docs_note=(
        "Reads ``members_can_create_public_repositories`` from "
        "``GET /orgs/{org}`` (the same fetch ORG-001 / ORG-002 / ORG-007 "
        "use) and fires when it is ``true``. ``false`` passes. When repository "
        "creation is disabled for members altogether "
        "(``members_can_create_repositories: false``) the rule passes, since "
        "the public sub-setting is then moot. The field is only returned to an "
        "org-owner-scoped token (``admin:org``); when absent the rule passes "
        "with an 'unavailable' note rather than guessing, so a low-scope token "
        "never produces a false finding."
    ),
)


def check(ctx: SCMOrgContext) -> Finding:
    meta = ctx.org_meta
    if not isinstance(meta, dict):
        return RULE.pass_finding(
            org_resource(ctx),
            "Organization settings were not available (see warnings); the "
            "member repository-creation policy could not be read.",
        )
    if "members_can_create_public_repositories" not in meta:
        return RULE.pass_finding(
            org_resource(ctx),
            "The token cannot read the organization's member "
            "repository-creation policy (needs ``admin:org``); not "
            "evaluated.",
        )
    # If members can't create repositories at all, the public sub-setting is
    # moot. GitHub may still report it true, so don't fire on that case.
    if meta.get("members_can_create_repositories") is False:
        return RULE.pass_finding(
            org_resource(ctx),
            f"Organization ``{ctx.org}`` does not let members create "
            "repositories, so member-created public repos are not possible.",
        )
    if meta.get("members_can_create_public_repositories") is not True:
        return RULE.pass_finding(
            org_resource(ctx),
            f"Organization ``{ctx.org}`` restricts public-repository "
            "creation (members cannot create public repos).",
        )
    return RULE.fail_finding(
        org_resource(ctx),
        f"Organization ``{ctx.org}`` lets any member create public "
        "repositories: a member can publish internal source code, secrets, "
        "or data to the internet with no review. Limit public-repo creation "
        "to owners.",
    )
