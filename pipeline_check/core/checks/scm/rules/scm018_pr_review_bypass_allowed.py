"""SCM-018. Required pull-request reviews can be bypassed.

A protection rule that requires reviews (SCM-002) but lists users,
teams, or apps in ``bypass_pull_request_allowances`` lets those
identities merge a PR without the configured approving review
count. The control becomes advisory for everyone in the list: the
gate documents intent rather than reality, exactly the failure mode
SCM-002's known-FP note flagged for follow-up.
"""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import SCMRepoSnapshot, default_branch_name, repo_resource

RULE = Rule(
    id="SCM-018",
    title="Required PR reviews can be bypassed by named identities",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-1",),
    esf=("ESF-S-CHANGE-CONTROL",),
    cwe=("CWE-269",),
    recommendation=(
        "In the default-branch protection rule, clear "
        "``Allow specified actors to bypass required pull requests`` "
        "(``required_pull_request_reviews.bypass_pull_request_"
        "allowances`` in the API). Required reviews are only as "
        "strong as the bypass list. If a release-bot account needs "
        "to merge automated PRs, prefer a separate protection rule "
        "for the bot's branch namespace rather than a bypass entry "
        "on the default branch."
    ),
    docs_note=(
        "Reads ``required_pull_request_reviews.bypass_pull_request_"
        "allowances`` from the branch protection payload. Fires when "
        "any of ``users`` / ``teams`` / ``apps`` is non-empty. "
        "Surfaces the counts so the operator can locate the bypass "
        "entries in the GitHub UI without re-running the audit "
        "manually."
    ),
    incident_refs=(
        "Multiple GitHub Security Lab writeups attribute "
        "post-incident review-control gaps to legacy bypass entries: "
        "a contractor onboarded years earlier is listed in the "
        "allowance, a compromise of that contractor account merges "
        "tampered code despite the team having added required "
        "reviews on the default branch.",
    ),
)


def _count_entries(allowance: Any) -> tuple[int, int, int]:
    """Return ``(users, teams, apps)`` counts from a bypass payload.

    GitHub returns each slot as a list of objects with ``login`` /
    ``slug`` keys. Treat anything non-list as zero, the FP/FN guard
    pattern shared by the rest of the rule pack.
    """
    if not isinstance(allowance, dict):
        return (0, 0, 0)
    users = allowance.get("users")
    teams = allowance.get("teams")
    apps = allowance.get("apps")
    return (
        len(users) if isinstance(users, list) else 0,
        len(teams) if isinstance(teams, list) else 0,
        len(apps) if isinstance(apps, list) else 0,
    )


def check(snapshot: SCMRepoSnapshot) -> Finding:
    branch = default_branch_name(snapshot)
    protection = snapshot.default_branch_protection
    if not isinstance(protection, dict):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                f"Default branch ``{branch}`` has no protection rule "
                f"to evaluate. See SCM-001."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    reviews = protection.get("required_pull_request_reviews")
    if not isinstance(reviews, dict):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                f"Default branch ``{branch}`` has no required-review "
                f"block to evaluate. See SCM-002."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    allowance = reviews.get("bypass_pull_request_allowances")
    n_users, n_teams, n_apps = _count_entries(allowance)
    total = n_users + n_teams + n_apps
    passed = total == 0
    if passed:
        desc = (
            f"Default branch ``{branch}`` does not list any identity "
            f"in the required-review bypass allowance."
        )
    else:
        parts: list[str] = []
        if n_users:
            parts.append(f"{n_users} user(s)")
        if n_teams:
            parts.append(f"{n_teams} team(s)")
        if n_apps:
            parts.append(f"{n_apps} app(s)")
        breakdown = ", ".join(parts)
        desc = (
            f"Default branch ``{branch}`` lists {breakdown} in "
            f"``bypass_pull_request_allowances``. The required-review "
            f"count from SCM-002 is unenforced for those identities; "
            f"any one of them can merge a self-authored PR with zero "
            f"second-set-of-eyes review."
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=repo_resource(snapshot), description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
