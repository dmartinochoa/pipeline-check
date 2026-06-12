"""ORG-012. New org repos get Dependabot alerts but not security updates."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import SCMOrgContext, org_resource

_ALERTS = "dependabot_alerts_enabled_for_new_repositories"
_UPDATES = "dependabot_security_updates_enabled_for_new_repositories"

RULE = Rule(
    id="ORG-012",
    title="New repositories get Dependabot alerts but not security updates",
    severity=Severity.LOW,
    owasp=("CICD-SEC-3", "CICD-SEC-10"),
    cwe=("CWE-1104",),
    recommendation=(
        "Turn on ``Automatically enable for new repositories`` for Dependabot "
        "security updates (Org Settings -> Code security -> Dependabot "
        "security updates). The organization already turns on Dependabot "
        "alerts by default for new repos (so a vulnerable dependency is "
        "surfaced), but without security updates every new repo only gets the "
        "alert, with no automatic pull request that bumps the dependency to a "
        "fixed version. Teams then patch by hand, slowly or not at all. "
        "Enabling the security-updates default closes the loop from 'a "
        "vulnerable dependency was detected' to 'a fix PR is waiting'. The "
        "per-repo analog is SCM-005."
    ),
    docs_note=(
        "Reads ``dependabot_alerts_enabled_for_new_repositories`` and "
        "``dependabot_security_updates_enabled_for_new_repositories`` from "
        "``GET /orgs/{org}`` (the same fetch ORG-001 / ORG-002 use) and fires "
        "only when alerts are on for new repos but security updates are not, "
        "the org-default half-adoption. When Dependabot alerts are off for new "
        "repos the rule passes (security updates require alerts first, and the "
        "field is plan-dependent), so an org without Dependabot never produces "
        "a false finding. When the fields are absent (low scope) the rule "
        "passes with a note. The org-default analog of SCM-005."
    ),
)


def check(ctx: SCMOrgContext) -> Finding:
    meta = ctx.org_meta
    if not isinstance(meta, dict):
        return RULE.pass_finding(
            org_resource(ctx),
            "Organization settings were not available (see warnings); the "
            "new-repository Dependabot defaults could not be read.",
        )
    if _UPDATES not in meta:
        return RULE.pass_finding(
            org_resource(ctx),
            "The token cannot read the organization's new-repository "
            "Dependabot security-updates default (needs ``admin:org``); not "
            "evaluated.",
        )
    if meta.get(_ALERTS) is not True:
        return RULE.pass_finding(
            org_resource(ctx),
            f"Organization ``{ctx.org}`` does not enable Dependabot alerts by "
            "default for new repositories, so the security-updates default is "
            "not evaluated here (enable alerts first).",
        )
    if meta.get(_UPDATES) is True:
        return RULE.pass_finding(
            org_resource(ctx),
            f"Organization ``{ctx.org}`` enables both Dependabot alerts and "
            "security updates by default for new repositories.",
        )
    return RULE.fail_finding(
        org_resource(ctx),
        f"Organization ``{ctx.org}`` enables Dependabot alerts for new "
        "repositories but not security updates: every new repo surfaces a "
        "vulnerable dependency but gets no automatic fix pull request. Enable "
        "the security-updates default to close the detect-to-patch loop.",
    )
