"""ORG-003. The org lets any action run (no Actions allow-list)."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import SCMOrgContext, org_resource

RULE = Rule(
    id="ORG-003",
    title="Organization allows any GitHub Action to run (no allow-list)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    cwe=("CWE-829",),
    recommendation=(
        "Restrict which actions can run org-wide (Org Settings -> Actions "
        "-> Policies). Set ``allowed_actions`` to ``selected`` and curate "
        "the allow-list (GitHub-authored plus a vetted set of verified "
        "creators / specific actions), or at minimum ``local_only``. "
        "Leaving it at ``all`` lets every workflow in every repo pull in "
        "any third-party action by a mutable tag, so one compromised or "
        "typosquatted action (the tj-actions / reviewdog class) executes "
        "across the whole org with each consuming workflow's token."
    ),
    docs_note=(
        "Reads ``allowed_actions`` from ``GET /orgs/{org}/actions/"
        "permissions`` and fires when it is ``all``. ``selected`` "
        "(curated allow-list) and ``local_only`` (only actions defined in "
        "the same repo) pass. The endpoint needs a token with the "
        "``actions`` (or org-admin) scope; when unavailable the rule "
        "passes with a note rather than guessing. An org that has disabled "
        "Actions entirely (``enabled_repositories: none``) also passes, "
        "since no third-party action can run."
    ),
)


def check(ctx: SCMOrgContext) -> Finding:
    perms = ctx.actions_permissions
    if not isinstance(perms, dict):
        return RULE.pass_finding(
            org_resource(ctx),
            "The organization's Actions policy was not available (needs a "
            "token with the ``actions`` / org-admin scope); not evaluated.",
        )
    if perms.get("enabled_repositories") == "none":
        return RULE.pass_finding(
            org_resource(ctx),
            f"Organization ``{ctx.org}`` has GitHub Actions disabled for "
            "all repositories; no third-party action can run.",
        )
    allowed = perms.get("allowed_actions")
    if allowed != "all":
        shown = allowed if isinstance(allowed, str) else "restricted"
        return RULE.pass_finding(
            org_resource(ctx),
            f"Organization ``{ctx.org}`` restricts which actions can run "
            f"(allowed_actions: ``{shown}``).",
        )
    return RULE.fail_finding(
        org_resource(ctx),
        f"Organization ``{ctx.org}`` allows any GitHub Action to run "
        "(allowed_actions: ``all``): every workflow can pull in any "
        "third-party action by a mutable tag, so one compromised or "
        "typosquatted action runs org-wide with the consuming token.",
    )
