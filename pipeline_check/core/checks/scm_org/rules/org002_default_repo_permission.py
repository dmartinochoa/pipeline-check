"""ORG-002. Every member gets write-or-higher access to every org repo."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import SCMOrgContext, org_resource

# GitHub's org-wide base permission. ``none`` / ``read`` are least-
# privilege; ``write`` lets every member push to every repo and ``admin``
# additionally lets them change settings, both far beyond least privilege.
_BROAD_PERMISSIONS = frozenset({"write", "admin"})

RULE = Rule(
    id="ORG-002",
    title="Organization default member permission grants write to every repo",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-269",),
    recommendation=(
        "Set the organization's ``Base permissions`` (Org Settings -> "
        "Member privileges) to ``Read`` or ``No permission`` and grant "
        "write/admin per-repository through teams. A ``Write`` or "
        "``Admin`` base permission means every member can push to (or "
        "reconfigure) every repository in the org, so one compromised "
        "member account can tamper with any project's code. Least "
        "privilege scopes write access to the repos a member actually "
        "works on."
    ),
    docs_note=(
        "Reads ``default_repository_permission`` from ``GET /orgs/{org}`` "
        "and fires when it is ``write`` or ``admin``. ``read`` / ``none`` "
        "pass. The field is only returned to an org-owner-scoped token "
        "(``admin:org``); when absent the rule passes with an "
        "'unavailable' note rather than guessing."
    ),
)


def check(ctx: SCMOrgContext) -> Finding:
    meta = ctx.org_meta
    if not isinstance(meta, dict):
        return RULE.pass_finding(
            org_resource(ctx),
            "Organization settings were not available (see warnings); the "
            "default repository permission could not be read.",
        )
    if "default_repository_permission" not in meta:
        return RULE.pass_finding(
            org_resource(ctx),
            "The token cannot read the organization's base permission "
            "(needs ``admin:org``); not evaluated.",
        )
    perm = meta.get("default_repository_permission")
    perm_str = perm if isinstance(perm, str) else "unknown"
    if perm_str not in _BROAD_PERMISSIONS:
        return RULE.pass_finding(
            org_resource(ctx),
            f"Organization ``{ctx.org}`` base member permission is "
            f"``{perm_str}`` (least privilege; write is granted per repo).",
        )
    return RULE.fail_finding(
        org_resource(ctx),
        f"Organization ``{ctx.org}`` grants every member ``{perm_str}`` "
        "access to every repository by default: one compromised member "
        "account can tamper with any project. Scope write to teams per "
        "repository instead.",
    )
