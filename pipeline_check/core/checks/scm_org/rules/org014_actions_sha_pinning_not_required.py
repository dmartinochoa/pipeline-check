"""ORG-014. Org Actions policy does not require SHA-pinned actions."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import SCMOrgContext, org_resource

RULE = Rule(
    id="ORG-014",
    title="Organization does not require SHA-pinned actions",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3", "CICD-SEC-8"),
    cwe=("CWE-829", "CWE-1357"),
    recommendation=(
        "Turn on the organization's SHA-pinning policy (Org Settings -> "
        "Actions -> General -> Policies -> \"Require actions to be pinned "
        "to a full-length commit SHA\"), or set ``sha_pinning_required: "
        "true`` via ``PUT /orgs/{org}/actions/permissions``. GitHub now "
        "enforces the pin at the platform level, so an action referenced "
        "by a mutable tag (``@v4``) or branch is rejected org-wide before "
        "it can run. This is the native complement to GHA-001: rather than "
        "flagging each unpinned ``uses:`` after the fact, the org control "
        "stops a retagged / backdoored action (the tj-actions/changed-files "
        "class, CVE-2025-30066) from executing in any repo."
    ),
    docs_note=(
        "Reads the ``sha_pinning_required`` field on "
        "``GET /orgs/{org}/actions/permissions`` (the same endpoint "
        "ORG-003 uses, so no extra fetch). Fires when the field is present "
        "and ``false``. Passes when it is ``true``, and passes with a note "
        "when the field is absent (GitHub Enterprise Server or an older API "
        "version that predates the policy) or the endpoint is unavailable. "
        "The org-governance complement to GHA-001 (per-workflow unpinned "
        "``uses:``). Needs a token with the ``admin:org`` scope."
    ),
    known_fp=(
        "An org that pins actions by convention or via a CI lint (rather "
        "than the platform policy) is genuinely pinned but still flagged, "
        "because the native enforcement is off and nothing stops a new repo "
        "from skipping the convention. Turn the policy on to make the "
        "guarantee enforced, or suppress at the org level with that "
        "rationale.",
    ),
)


def check(ctx: SCMOrgContext) -> Finding:
    perms = ctx.actions_permissions
    if not isinstance(perms, dict):
        return RULE.pass_finding(
            org_resource(ctx),
            "The organization's Actions permissions were not available "
            "(needs a token with the ``admin:org`` scope); not evaluated.",
        )
    required = perms.get("sha_pinning_required")
    if required is None:
        return RULE.pass_finding(
            org_resource(ctx),
            "The organization's Actions policy does not report a "
            "``sha_pinning_required`` field (GitHub Enterprise Server or an "
            "API version that predates the SHA-pinning policy); not "
            "evaluated.",
        )
    if required:
        return RULE.pass_finding(
            org_resource(ctx),
            f"Organization ``{ctx.org}`` requires actions to be pinned to a "
            "full-length commit SHA (``sha_pinning_required: true``).",
        )
    return RULE.fail_finding(
        org_resource(ctx),
        f"Organization ``{ctx.org}`` does not require SHA-pinned actions "
        "(``sha_pinning_required: false``), so any repo can reference an "
        "action by a mutable tag or branch. A retagged or backdoored "
        "action then runs org-wide, the exact vector GitHub's native "
        "pinning policy closes.",
    )
