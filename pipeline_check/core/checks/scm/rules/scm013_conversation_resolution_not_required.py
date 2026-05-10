"""SCM-013. Default branch protection does not require conversation resolution.

Maps to CIS Software Supply Chain Security Guide section 1.1.5.
Without ``Require conversation resolution before merging``, a PR
can land while review comments are still open. Reviewers' security
concerns ("does this leak the API key in logs?", "is this taint
sink protected?") become permanently lost once the PR merges and
the review thread closes; reviewers stop bothering.
"""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import SCMRepoSnapshot, default_branch_name, repo_resource

RULE = Rule(
    id="SCM-013",
    title="Default branch protection does not require conversation resolution",
    severity=Severity.LOW,
    owasp=("CICD-SEC-1",),
    esf=("ESF-S-CHANGE-CONTROL",),
    cwe=("CWE-1059",),
    recommendation=(
        "In the default-branch protection rule, enable ``Require "
        "conversation resolution before merging``. PRs cannot land "
        "until every review comment is marked resolved. The friction "
        "is small (the PR author clicks ``Resolve`` after "
        "addressing) and the payoff is concrete: review comments "
        "can't be ignored to ship faster."
    ),
    docs_note=(
        "Reads ``required_conversation_resolution.enabled`` from the "
        "branch protection payload. Fires when the value is False or "
        "the field is missing. Severity is LOW because the rule "
        "documents process discipline rather than a structural "
        "vulnerability — but unresolved security comments are a "
        "common upstream cause of incidents."
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
    rcr = protection.get("required_conversation_resolution")
    enabled = False
    if isinstance(rcr, dict):
        enabled = bool(rcr.get("enabled"))
    passed = enabled
    desc = (
        f"Default branch ``{branch}`` requires conversation "
        f"resolution before merge."
        if passed else
        f"Default branch ``{branch}`` does not require conversation "
        f"resolution. Open review comments don't block the merge — "
        f"reviewers' concerns about secrets, taint sinks, and other "
        f"security questions can be ignored to ship faster."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=repo_resource(snapshot), description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
