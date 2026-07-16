"""ORG-015. Organization does not enforce immutable releases."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import SCMOrgContext, org_resource

RULE = Rule(
    id="ORG-015",
    title="Organization does not enforce immutable releases",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-1",),
    cwe=("CWE-353",),
    recommendation=(
        "Enforce immutable releases org-wide (Org Settings -> Repository -> "
        "Immutable releases -> All repositories), or set "
        "``enforced_repositories: all`` via "
        "``PUT /orgs/{org}/settings/immutable-releases``. Once enforced, a "
        "published release's assets are locked and its Git tag is protected, "
        "so an attacker who compromises a maintainer account can no longer "
        "swap a release binary or repoint a tag after downstream consumers "
        "have pinned to it. Immutable releases also carry a build "
        "attestation for verifiable integrity. ``selected`` leaves every "
        "unlisted repo mutable; prefer ``all`` unless a documented subset is "
        "intentional."
    ),
    docs_note=(
        "Reads ``enforced_repositories`` from "
        "``GET /orgs/{org}/settings/immutable-releases`` and fires when it "
        "is ``\"none\"`` (no repo is enforced). Passes on ``\"all\"`` and "
        "passes with a partial-coverage note on ``\"selected\"`` (some repos "
        "enforced, the rest still mutable). Passes with an unavailable note "
        "when the endpoint is missing (GitHub Enterprise Server or an API "
        "version predating the GA control) or the token lacks scope. The "
        "org-governance analog of the per-release attestation posture; needs "
        "a token with the ``admin:org`` scope."
    ),
    known_fp=(
        "An org that scopes immutable-release enforcement to a documented "
        "subset via ``selected`` passes (it is not flagged). An org that "
        "deliberately keeps releases mutable (rapid-iteration internal "
        "tooling with no external consumers) can suppress at the org level "
        "with that rationale.",
    ),
)


def check(ctx: SCMOrgContext) -> Finding:
    policy = ctx.immutable_releases
    if not isinstance(policy, dict):
        return RULE.pass_finding(
            org_resource(ctx),
            "The organization's immutable-releases policy was not available "
            "(GitHub Enterprise Server, an API version predating the "
            "control, or a token without the ``admin:org`` scope); not "
            "evaluated.",
        )
    enforced = policy.get("enforced_repositories")
    if enforced == "all":
        return RULE.pass_finding(
            org_resource(ctx),
            f"Organization ``{ctx.org}`` enforces immutable releases across "
            "all repositories (``enforced_repositories: all``).",
        )
    if enforced == "selected":
        return RULE.pass_finding(
            org_resource(ctx),
            f"Organization ``{ctx.org}`` enforces immutable releases on a "
            "selected subset of repositories; repositories outside the list "
            "still publish mutable releases. Prefer ``all`` unless the "
            "subset is intentional.",
        )
    return RULE.fail_finding(
        org_resource(ctx),
        f"Organization ``{ctx.org}`` does not enforce immutable releases "
        "(``enforced_repositories: none``), so a published release's assets "
        "and Git tag can be altered after the fact. A compromised "
        "maintainer account can then swap a release binary or repoint a tag "
        "under consumers who have already pinned to it.",
    )
