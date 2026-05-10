"""SCM-012. Default branch protection does not dismiss stale reviews.

Maps to CIS Software Supply Chain Security Guide section 1.1.5.
Without ``Dismiss stale pull request approvals when new commits are
pushed``, a reviewer's approval persists even after the PR author
force-pushes a different change. The reviewer signed off on the
old diff; the new diff merges with their stale approval intact.
This is the classic "approval-time-of-check vs merge-time-of-use"
vulnerability and a routine red-team primitive.
"""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import SCMRepoSnapshot, default_branch_name, repo_resource

RULE = Rule(
    id="SCM-012",
    title="Default branch protection keeps stale reviews after a push",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-1",),
    esf=("ESF-S-CHANGE-CONTROL",),
    cwe=("CWE-367",),
    recommendation=(
        "In the default-branch protection rule, enable ``Dismiss "
        "stale pull request approvals when new commits are pushed``. "
        "Approvals will be cleared every time the PR head moves; "
        "the reviewer has to re-approve the latest diff before "
        "merge, closing the time-of-check / time-of-use gap an "
        "attacker can exploit by amending the branch after approval."
    ),
    docs_note=(
        "Reads ``required_pull_request_reviews.dismiss_stale_reviews`` "
        "from the branch protection payload. Fires when the value is "
        "False or the field is missing. ``SCM-002`` ensures a review "
        "is required at all; this rule ensures the approval the "
        "team relies on actually corresponds to the diff being "
        "merged."
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
    reviews = protection.get("required_pull_request_reviews")
    dismiss = False
    if isinstance(reviews, dict):
        dismiss = bool(reviews.get("dismiss_stale_reviews"))
    passed = dismiss
    desc = (
        f"Default branch ``{branch}`` dismisses stale reviews when "
        f"new commits are pushed."
        if passed else
        f"Default branch ``{branch}`` does not dismiss stale reviews. "
        f"A reviewer's approval persists across force-pushes that "
        f"land different code; an attacker can get approval on a "
        f"benign diff, then amend the branch with a malicious change "
        f"and merge with the original approval intact."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=repo_resource(snapshot), description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
