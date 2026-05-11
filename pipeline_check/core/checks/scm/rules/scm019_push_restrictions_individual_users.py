"""SCM-019. Direct-push allowlist contains individual user accounts.

``restrictions`` on a branch protection rule limits who can push
directly to the protected branch (independent of the PR-review
gates). Personal user accounts in this allowlist are personal-
compromise vectors: a single phished credential or stolen SSH key
maps directly to a push on the production branch. Teams and apps
are usually safer choices — teams roll over with org changes; apps
authenticate via dedicated tokens with narrow scope.

The rule is audit-style: it lists the named users so the operator
can review the allowlist without re-opening the GitHub UI.
"""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import SCMRepoSnapshot, default_branch_name, repo_resource

RULE = Rule(
    id="SCM-019",
    title="Push restrictions allowlist names individual users",
    severity=Severity.LOW,
    owasp=("CICD-SEC-1",),
    esf=("ESF-S-CHANGE-CONTROL",),
    cwe=("CWE-269",),
    recommendation=(
        "In the default-branch protection rule, audit the "
        "``Restrict who can push to matching branches`` allowlist "
        "(``restrictions`` in the API). Move each individual user "
        "into a GitHub team and add the team instead, or replace "
        "with a GitHub App / bot service account when the entry is "
        "an automation. Named user entries are personal-compromise "
        "vectors that bypass every PR-review gate on the branch."
    ),
    docs_note=(
        "Reads ``restrictions.users`` from the branch protection "
        "payload. Fires when the list is non-empty. ``restrictions`` "
        "itself being absent is the default GitHub posture (no push "
        "allowlist; review gates govern access) and passes this "
        "rule. Teams and apps in ``restrictions`` are not flagged — "
        "the rule audits the personal-account subset specifically."
    ),
    known_fp=(
        "A break-glass admin account intentionally listed for "
        "incident response is a legitimate use case. Suppress via "
        "ignore-file once the account's access has been reviewed "
        "(MFA, hardware token, audit-logged use).",
    ),
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
    restrictions = protection.get("restrictions")
    # Absent restrictions: default GitHub posture, no push allowlist.
    # Review gates govern access. This rule passes silently — the
    # rule scope is the named-user subset of the allowlist, not the
    # presence of an allowlist itself.
    if not isinstance(restrictions, dict):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                f"Default branch ``{branch}`` has no push-restriction "
                f"allowlist (review gates govern direct-push access)."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    users_raw = restrictions.get("users")
    users = users_raw if isinstance(users_raw, list) else []
    user_logins: list[str] = []
    for entry in users:
        # GitHub returns each user as a JSON object with ``login``.
        # Fixture writers sometimes shortcut to a bare string; accept
        # both shapes the same way the other SCM rules do.
        if isinstance(entry, dict):
            login = entry.get("login")
            if isinstance(login, str) and login:
                user_logins.append(login)
        elif isinstance(entry, str) and entry:
            user_logins.append(entry)
    passed = not user_logins
    if passed:
        desc = (
            f"Default branch ``{branch}`` push-restriction allowlist "
            f"names no individual users (teams / apps only)."
        )
    else:
        sample = ", ".join(f"@{u}" for u in user_logins[:5])
        if len(user_logins) > 5:
            sample += f", ... (+{len(user_logins) - 5} more)"
        desc = (
            f"Default branch ``{branch}`` push-restriction allowlist "
            f"names {len(user_logins)} individual user(s): {sample}. "
            f"Each personal account is a direct-push vector on the "
            f"default branch; a single phished credential lands a "
            f"tampered commit without review."
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=repo_resource(snapshot), description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
