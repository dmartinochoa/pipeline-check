"""ORG-005. GitHub Actions is allowed to approve pull requests."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import SCMOrgContext, org_resource

RULE = Rule(
    id="ORG-005",
    title="Organization lets GitHub Actions approve pull requests",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-1",),
    cwe=("CWE-863",),
    recommendation=(
        "Turn off ``Allow GitHub Actions to create and approve pull "
        "requests`` (Org Settings -> Actions -> General -> Workflow "
        "permissions). When it is on, a workflow running with the "
        "``GITHUB_TOKEN`` can submit an approving review, which can satisfy "
        "a required-review branch-protection rule without a human ever "
        "looking at the change. A merge-bot or an attacker who can trigger "
        "a workflow then self-approves a malicious PR. Require approvals "
        "from human reviewers (or a separate identity) instead."
    ),
    docs_note=(
        "Reads ``can_approve_pull_request_reviews`` from "
        "``GET /orgs/{org}/actions/permissions/workflow`` (the same fetch "
        "ORG-004 uses) and fires when it is ``true``. The endpoint needs a "
        "token with the ``actions`` / org-admin scope; when unavailable the "
        "rule passes with a note. Individual repos can still override this "
        "org default."
    ),
)


def check(ctx: SCMOrgContext) -> Finding:
    perms = ctx.actions_workflow_permissions
    if not isinstance(perms, dict):
        return RULE.pass_finding(
            org_resource(ctx),
            "The organization's workflow-permission setting was not "
            "available (needs a token with the ``actions`` / org-admin "
            "scope); not evaluated.",
        )
    if "can_approve_pull_request_reviews" not in perms:
        return RULE.pass_finding(
            org_resource(ctx),
            "The token cannot read whether Actions may approve pull "
            "requests; not evaluated.",
        )
    if perms.get("can_approve_pull_request_reviews") is not True:
        return RULE.pass_finding(
            org_resource(ctx),
            f"Organization ``{ctx.org}`` does not let GitHub Actions "
            "approve pull requests.",
        )
    return RULE.fail_finding(
        org_resource(ctx),
        f"Organization ``{ctx.org}`` lets GitHub Actions approve pull "
        "requests: a workflow can self-approve a PR with the GITHUB_TOKEN "
        "and satisfy a required-review gate without a human reviewer.",
    )
