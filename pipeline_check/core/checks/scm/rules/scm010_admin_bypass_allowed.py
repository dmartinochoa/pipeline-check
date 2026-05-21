"""SCM-010. Branch protection rule does not enforce against administrators.

Maps to CIS Software Supply Chain Security Guide section 1.1.5
(any change to code requires review). A protection rule that lets
admins skip every gate is paper armor — every protection knob the
team configured (required reviews, required status checks, signed
commits, force-push denial) is opt-in for admin accounts.
"""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import SCMRepoSnapshot, default_branch_name, repo_resource

RULE = Rule(
    id="SCM-010",
    title="Branch protection allows administrators to bypass",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-1",),
    esf=("ESF-S-CHANGE-CONTROL",),
    cwe=("CWE-269",),
    recommendation=(
        "In the default-branch protection rule, enable ``Do not "
        "allow bypassing the above settings`` (a.k.a. ``Include "
        "administrators``). Otherwise every other knob you set "
        "(required reviews, status checks, signed commits) becomes "
        "advisory rather than enforced. A compromised admin account "
        "is also a much shorter path to a tampered release than a "
        "compromised contributor account, so admins are exactly the "
        "identity the gate needs to apply to."
    ),
    docs_note=(
        "Reads ``enforce_admins.enabled`` from the branch protection "
        "payload. Fires when the value is False or the field is "
        "missing. Pairs with every other SCM-NNN rule that reads a "
        "branch-protection knob — without enforce_admins, those "
        "rules document intent rather than reality."
    ),
    exploit_example=(
        "# Vulnerable: ``enforce_admins: false`` (or its absence)\n"
        "# lets repo admins push directly to ``main``, skip\n"
        "# required reviews, and bypass status checks. An admin's\n"
        "# token leak escalates straight to ``main``-write.\n"
        "# GET /repos/myorg/myrepo/branches/main/protection:\n"
        "{\n"
        "  \"required_pull_request_reviews\": {\n"
        "    \"required_approving_review_count\": 2\n"
        "  },\n"
        "  \"enforce_admins\": {\"enabled\": false}\n"
        "}\n"
        "\n"
        "# Safe: ``enforce_admins: true`` so the protection\n"
        "# applies to admins too. Reviews and status checks are\n"
        "# no longer bypassable.\n"
        "# PUT /repos/myorg/myrepo/branches/main/protection:\n"
        "{\n"
        "  \"required_pull_request_reviews\": {\n"
        "    \"required_approving_review_count\": 2\n"
        "  },\n"
        "  \"enforce_admins\": {\"enabled\": true}\n"
        "}"
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
    enforce = protection.get("enforce_admins")
    enforced = False
    if isinstance(enforce, dict):
        enforced = bool(enforce.get("enabled"))
    elif isinstance(enforce, bool):
        # The legacy shape of this field was a bare boolean; modern
        # API responses wrap it in ``{"enabled": ...}`` but accept
        # both for compatibility with older fixtures.
        enforced = enforce
    passed = enforced
    desc = (
        f"Default branch ``{branch}`` enforces protection rules "
        f"against administrators."
        if passed else
        f"Default branch ``{branch}`` lets administrators bypass "
        f"the protection rule. Required reviews, status checks, "
        f"signed commits, and force-push denial are advisory rather "
        f"than enforced when the actor is an admin."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=repo_resource(snapshot), description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
