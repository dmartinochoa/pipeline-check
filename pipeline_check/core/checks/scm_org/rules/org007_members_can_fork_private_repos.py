"""ORG-007. The organization allows forking of private repositories."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import SCMOrgContext, org_resource

RULE = Rule(
    id="ORG-007",
    title="Organization allows forking of private repositories",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-200",),
    recommendation=(
        "Turn off ``Allow forking of private repositories`` (Org Settings "
        "-> Member privileges -> Repository forking). When it is on, any "
        "member can fork a private or internal repository to their personal "
        "account, where the org's branch protection, audit log, secret "
        "scanning, and 2FA policy no longer apply, and the copy persists "
        "after the member leaves. That moves source code outside the "
        "controls that govern the org, a data-exfiltration and IP-leak "
        "path that needs no exploit. Allow forking only for the specific "
        "repos that require it, and prefer forking within the org."
    ),
    docs_note=(
        "Reads ``members_can_fork_private_repositories`` from "
        "``GET /orgs/{org}`` (the same fetch ORG-001 / ORG-002 use) and "
        "fires when it is ``true``. ``false`` passes. The field is only "
        "returned to an org-owner-scoped token (``admin:org``); when absent "
        "the rule passes with an 'unavailable' note rather than guessing, so "
        "a low-scope token never produces a false finding. Individual repos "
        "can still restrict forking below this org default."
    ),
)


def check(ctx: SCMOrgContext) -> Finding:
    meta = ctx.org_meta
    if not isinstance(meta, dict):
        return RULE.pass_finding(
            org_resource(ctx),
            "Organization settings were not available (see warnings); the "
            "private-repository forking policy could not be read.",
        )
    if "members_can_fork_private_repositories" not in meta:
        return RULE.pass_finding(
            org_resource(ctx),
            "The token cannot read the organization's private-repository "
            "forking policy (needs ``admin:org``); not evaluated.",
        )
    if meta.get("members_can_fork_private_repositories") is not True:
        return RULE.pass_finding(
            org_resource(ctx),
            f"Organization ``{ctx.org}`` does not allow forking of private "
            "repositories.",
        )
    return RULE.fail_finding(
        org_resource(ctx),
        f"Organization ``{ctx.org}`` allows forking of private "
        "repositories: any member can fork private or internal source code "
        "to a personal account, outside the org's branch protection, audit "
        "log, and secret scanning. Restrict forking to the repos that need "
        "it.",
    )
