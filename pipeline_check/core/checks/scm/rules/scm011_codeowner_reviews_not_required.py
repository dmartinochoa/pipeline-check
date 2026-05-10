"""SCM-011. Default branch protection does not require CODEOWNERS reviews.

Maps to CIS Software Supply Chain Security Guide section 1.1.5
(any change to code requires review from authorized personnel)
and OpenSSF Scorecard's Code-Review check. CODEOWNERS-required
review is the mechanism that maps "authorized personnel" to a
specific path in the repo: a change to ``infra/`` requires sign-off
from the platform team, a change to ``frontend/`` from the FE team.
Without it, any reviewer can approve any change.
"""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import SCMRepoSnapshot, default_branch_name, repo_resource

RULE = Rule(
    id="SCM-011",
    title="Default branch protection does not require CODEOWNERS reviews",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-1",),
    esf=("ESF-S-CHANGE-CONTROL",),
    cwe=("CWE-732",),
    recommendation=(
        "In the default-branch protection rule, enable ``Require "
        "review from Code Owners``. Add a ``CODEOWNERS`` file at "
        "``.github/CODEOWNERS`` (or ``docs/CODEOWNERS``) mapping "
        "directories to the team or individual responsible. The "
        "GitHub UI auto-requests review from the matched owners on "
        "every PR that touches a covered path; combined with this "
        "branch-protection knob, the merge is blocked until they "
        "approve."
    ),
    docs_note=(
        "Reads ``required_pull_request_reviews.require_code_owner_"
        "reviews`` from the branch protection payload. Fires when "
        "the value is False or the field is missing. ``SCM-002`` "
        "covers the bare review-count knob; this rule scopes "
        "specifically to whose review counts. The check evaluates "
        "only the protection-rule toggle; verifying that an actual "
        "``CODEOWNERS`` file exists at ``.github/CODEOWNERS`` (and "
        "covers the right paths) is left to the recommendation, "
        "since the GitHub API surfaces the file's presence as a "
        "separate contents request the SCM provider does not fetch."
    ),
    known_fp=(
        "Single-team repos where every contributor is a code owner "
        "of every path don't need the routing CODEOWNERS provides — "
        "but the protection knob still helps when a new team member "
        "joins. Suppress via ignore-file when the team intentionally "
        "stays flat.",
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
        required = bool(reviews.get("require_code_owner_reviews"))
    passed = required
    desc = (
        f"Default branch ``{branch}`` requires reviews from CODEOWNERS."
        if passed else
        f"Default branch ``{branch}`` does not require reviews from "
        f"CODEOWNERS. Any reviewer can approve any change; "
        f"path-scoped sign-off (a change to ``infra/`` requires "
        f"infra team approval) is unenforced."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=repo_resource(snapshot), description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
