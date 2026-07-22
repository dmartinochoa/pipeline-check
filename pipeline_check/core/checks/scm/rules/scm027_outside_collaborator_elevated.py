"""SCM-027. Outside collaborator has elevated (write+) permissions."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import (
    SCMRepoSnapshot,
    archived_state_label,
    github_only_skip,
    repo_resource,
)

RULE = Rule(
    id="SCM-027",
    title="Outside collaborator holds write / maintain / admin access",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2", "CICD-SEC-5"),
    esf=("ESF-D-ACCESS-CONTROL",),
    cwe=("CWE-269", "CWE-284"),
    recommendation=(
        "Audit Settings → Collaborators and teams → Outside "
        "collaborators. For each entry the rule flagged: either "
        "(a) downgrade the access to ``Read`` if the contributor "
        "only needs to clone / open PRs, or (b) move the account "
        "into the org as a member (so the org's centralized RBAC, "
        "SCIM, and access-review processes apply) before granting "
        "write access. Outside collaborators bypass the org's "
        "user-lifecycle controls: when the contractor's term "
        "ends, the entry stays until somebody manually removes it. "
        "A compromised outside-collab account with ``push`` access "
        "is the direct path to bypassing branch protection: that "
        "account can push code that SCM-021 (Actions self-"
        "approval) or SCM-018 (PR bypass allowance) clears through "
        "every required-review gate. Maintain / admin extends the "
        "blast radius to repo-config control."
    ),
    docs_note=(
        "Walks ``GET /repos/{owner}/{repo}/collaborators?"
        "affiliation=outside`` and flags every entry whose "
        "``permissions`` block has any of ``admin: true``, "
        "``maintain: true``, or ``push: true``. Read-only "
        "(``permissions.pull: true`` with no higher tier) and "
        "triage entries pass. Each finding's description names "
        "every elevated collaborator with the granular level so "
        "the operator can prioritize.\n\n"
        "Requires admin scope on the repo to enumerate the outside-"
        "collaborator list; without it the endpoint returns 403 "
        "and the rule passes silently with an unavailability note. "
        "The hydrator fetches a single page (``per_page=100``); "
        "in the rare case of more than 100 outside collaborators "
        "on one repo, the description appends a truncation note "
        "and asks for a manual audit."
    ),
    known_fp=(
        "Some flows legitimately grant write access to a vetted "
        "outside collaborator on a short-term basis (audit firm, "
        "incident responder, vendor escalation). The right "
        "compensating control is a calendar-bound suppression "
        "with the rationale and the expected revocation date; "
        "the rule itself should keep flagging the access so the "
        "revocation date is visible at every scan.",
    ),
    incident_refs=(
        "Long-running pattern across compromise postmortems: a "
        "former contributor's outside-collaborator entry retains "
        "``push`` access years after the engagement ended. The "
        "account is then taken over (often by credential stuffing "
        "or a leaked PAT), and the attacker pushes a tampered "
        "commit that lands without review because the access "
        "level itself is the gate.",
    ),
    exploit_example=(
        "# Vulnerable: an outside collaborator (a contractor, a\n"
        "# departed employee whose access wasn't fully revoked,\n"
        "# a security-researcher allowed in for a one-off audit)\n"
        "# carries ``write`` / ``maintain`` / ``admin`` on the\n"
        "# repo. The blast radius of their account compromise\n"
        "# is the same as an internal maintainer's.\n"
        "# GET /repos/myorg/myrepo/collaborators?affiliation=outside:\n"
        "[\n"
        "  {\n"
        "    \"login\": \"contractor-alice\",\n"
        "    \"role_name\": \"write\"\n"
        "  }\n"
        "]\n"
        "\n"
        "# Safe: outside collaborators carry ``read`` or ``triage``\n"
        "# only. If they need to land code, route through fork +\n"
        "# PR + internal-reviewer approval. Re-run access reviews\n"
        "# quarterly and revoke on engagement end.\n"
        "# PUT /repos/myorg/myrepo/collaborators/contractor-alice:\n"
        "{\n"
        "  \"permission\": \"read\"\n"
        "}"
    ),
)


# Permissions field shape from GitHub's REST API: a dict with
# boolean entries for the access tiers the user holds. ``admin``
# implies everything below it; ``maintain`` implies push + triage
# + pull; ``push`` implies triage + pull; ``triage`` and ``pull``
# are read-tier. The rule fails on any of {admin, maintain, push}.
_ELEVATED_FIELDS: tuple[str, ...] = ("admin", "maintain", "push")


def _elevated_level(perms: dict[str, Any]) -> str | None:
    """Return the *most-elevated* permission tier this user holds,
    or ``None`` when they only have triage / pull / nothing.

    The order in ``_ELEVATED_FIELDS`` is most-to-least privileged,
    so the first True wins and we report the highest tier.
    """
    for field in _ELEVATED_FIELDS:
        if perms.get(field) is True:
            return field
    return None


def check(snapshot: SCMRepoSnapshot) -> Finding:
    skip = github_only_skip(snapshot)
    if skip is not None:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=skip,
            recommendation=RULE.recommendation, passed=True,
        )
    if label := archived_state_label(snapshot):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                f"Repo is {label}; outside-collaborator check skipped."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    collabs = snapshot.outside_collaborators
    if collabs is None:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                "repos/collaborators?affiliation=outside endpoint "
                "unavailable (token likely lacks ``admin`` scope)."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    if not collabs:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description="No outside collaborators configured.",
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    for user in collabs:
        perms = user.get("permissions")
        if isinstance(perms, dict):
            level = _elevated_level(perms)
        else:
            # Partial payloads may carry only ``role_name``; treat an
            # elevated role there as the access level rather than
            # silently claiming the collaborator is read-only.
            role = user.get("role_name")
            level = (
                role if isinstance(role, str)
                and role in ("write", "maintain", "admin") else None
            )
        if level is None:
            continue
        login = user.get("login")
        label = login if isinstance(login, str) and login else "(unnamed)"
        offenders.append(f"{label}:{level}")
    truncated = len(collabs) == 100  # potential pagination boundary
    passed = not offenders
    if passed:
        desc = (
            f"All {len(collabs)} outside collaborator(s) are "
            "read-only."
        )
        if truncated:
            desc += (
                " NOTE: list returned exactly 100 entries; further "
                "pages exist and weren't audited by this scan — "
                "consider a manual review."
            )
    else:
        desc = (
            f"{len(offenders)} outside collaborator(s) hold "
            f"elevated permissions: {', '.join(offenders[:5])}"
            f"{'…' if len(offenders) > 5 else ''}. Each is one "
            f"compromised account away from pushing directly to "
            f"the repo without going through the org's user-"
            f"lifecycle controls."
        )
        if truncated:
            desc += (
                " NOTE: outside-collaborator list capped at 100; "
                "more entries may exist."
            )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=repo_resource(snapshot), description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
