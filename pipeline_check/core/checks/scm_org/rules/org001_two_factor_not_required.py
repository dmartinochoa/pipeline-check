"""ORG-001. The organization does not require two-factor authentication."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import SCMOrgContext, org_resource

RULE = Rule(
    id="ORG-001",
    title="Organization does not require two-factor authentication",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-308",),
    recommendation=(
        "Turn on ``Require two-factor authentication for everyone in the "
        "organization`` (Org Settings -> Authentication security). Without "
        "it, a single phished or reused member password is enough to push "
        "to repositories, approve pull requests, or mint tokens as that "
        "member. Note that enabling the requirement removes members and "
        "outside collaborators who don't have 2FA configured, so audit the "
        "member list first."
    ),
    docs_note=(
        "Reads ``two_factor_requirement_enabled`` from ``GET /orgs/{org}``. "
        "Fires when it is ``false``. The field is only returned to a token "
        "with org-owner scope (``admin:org`` / ``read:org``); when it is "
        "absent the rule passes with an 'unavailable' note rather than "
        "guessing, so a low-scope token never produces a false finding. "
        "Org-wide 2FA is the single highest-leverage account-takeover "
        "control and the flagship check of org-posture scanners "
        "(Legitify / Allstar)."
    ),
)


def check(ctx: SCMOrgContext) -> Finding:
    meta = ctx.org_meta
    if not isinstance(meta, dict):
        return RULE.pass_finding(
            org_resource(ctx),
            "Organization settings were not available (see warnings); the "
            "two-factor requirement could not be read.",
        )
    if "two_factor_requirement_enabled" not in meta:
        return RULE.pass_finding(
            org_resource(ctx),
            "The token cannot read the organization's two-factor "
            "requirement (needs ``admin:org`` / ``read:org``); not "
            "evaluated.",
        )
    required = meta.get("two_factor_requirement_enabled")
    if required is True:
        return RULE.pass_finding(
            org_resource(ctx),
            f"Organization ``{ctx.org}`` requires two-factor "
            "authentication for all members.",
        )
    return RULE.fail_finding(
        org_resource(ctx),
        f"Organization ``{ctx.org}`` does not require two-factor "
        "authentication: a single compromised member password can push "
        "code, approve PRs, or mint tokens as that member.",
    )
