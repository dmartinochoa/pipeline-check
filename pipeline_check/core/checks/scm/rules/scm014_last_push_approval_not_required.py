"""SCM-014. Default branch protection allows the most recent pusher to approve.

Maps to CIS Software Supply Chain Security Guide section 1.1.5.
Without ``Require approval of the most recent reviewable push``,
a contributor with two GitHub accounts (or two collaborating
contributors) can game the review requirement: account A pushes
the change, account B approves, then account A force-pushes a
tampered version that inherits B's approval. Requiring approval
of the most recent push closes that loop.
"""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import SCMRepoSnapshot, default_branch_name, repo_resource

RULE = Rule(
    id="SCM-014",
    title="Default branch protection does not require approval of the most recent push",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-1",),
    esf=("ESF-S-CHANGE-CONTROL",),
    cwe=("CWE-863",),
    recommendation=(
        "In the default-branch protection rule, enable ``Require "
        "approval of the most recent reviewable push``. The reviewer "
        "and the most recent pusher must be different identities; "
        "an attacker controlling one collaborator account can no "
        "longer ship a malicious diff under another collaborator's "
        "approval."
    ),
    docs_note=(
        "Reads ``required_pull_request_reviews.require_last_push_"
        "approval`` from the branch protection payload. Fires when "
        "the value is False or the field is missing. Pairs with "
        "SCM-012 (dismiss stale reviews) — both close the same "
        "approval-time-of-check / merge-time-of-use gap from "
        "different angles."
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
    required = False
    if isinstance(reviews, dict):
        required = bool(reviews.get("require_last_push_approval"))
    passed = required
    desc = (
        f"Default branch ``{branch}`` requires approval of the most "
        f"recent reviewable push."
        if passed else
        f"Default branch ``{branch}`` does not require approval of "
        f"the most recent push. A contributor with two collaborator "
        f"accounts (or two collaborating contributors) can push a "
        f"benign diff with one identity, get approval from the "
        f"other, then force-push a tampered version that merges "
        f"under the original approval."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=repo_resource(snapshot), description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
