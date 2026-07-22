"""SCM-009. Default branch protection allows branch deletion.

Maps to CIS Software Supply Chain Security Guide section 1.1.17
(default branches' commits are protected from being deleted /
rewritten). Sibling to SCM-007 (force-push): SCM-007 covers the
rewrite vector, SCM-009 covers the wholesale-delete vector. Either
collapses the audit trail; both should be off on a high-trust
default branch.
"""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import SCMRepoSnapshot, default_branch_name, repo_resource

RULE = Rule(
    id="SCM-009",
    title="Default branch protection allows branch deletion",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-1",),
    esf=("ESF-S-CHANGE-CONTROL",),
    cwe=("CWE-693",),
    recommendation=(
        "In the default-branch protection rule, set ``Allow "
        "deletions`` to ``Disabled``. A deleted default branch wipes "
        "every protection rule attached to it; an attacker with "
        "write access can delete the branch, recreate it from a "
        "tampered commit, and re-apply protection in a way that "
        "looks identical from the UI."
    ),
    docs_note=(
        "Reads ``allow_deletions.enabled`` from the branch protection "
        "payload. Fires when the value is True. Pairs with SCM-007 "
        "(force-push allowed) — the two flags together cover the "
        "complete rewrite-history attack class."
    ),
    exploit_example=(
        "# Vulnerable: ``allow_deletions: true`` lets anyone with\n"
        "# write access delete the default branch entirely. A\n"
        "# compromised token (leaked PAT, malicious workflow\n"
        "# running with ``contents: write``) erases the branch\n"
        "# along with the production deployment trail.\n"
        "# GET /repos/myorg/myrepo/branches/main/protection:\n"
        "{\n"
        "  \"allow_deletions\": {\"enabled\": true}\n"
        "}\n"
        "\n"
        "# Safe: branch deletion off. ``main`` cannot be deleted\n"
        "# via API or UI without first removing the protection\n"
        "# rule, which itself is an audited admin action.\n"
        "# PUT /repos/myorg/myrepo/branches/main/protection:\n"
        "{\n"
        "  \"allow_deletions\": {\"enabled\": false}\n"
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
    deletions = protection.get("allow_deletions")
    allowed = False
    if isinstance(deletions, dict):
        allowed = bool(deletions.get("enabled"))
    elif isinstance(deletions, bool):
        # Legacy / PUT-body shape carries a bare boolean (SCM-010
        # accepts the same for its knob).
        allowed = deletions
    passed = not allowed
    desc = (
        f"Default branch ``{branch}`` blocks deletion."
        if passed else
        f"Default branch ``{branch}`` allows deletion. An attacker "
        f"with write access can delete the branch outright, "
        f"recreate it from a tampered commit, and re-apply "
        f"protection in a way indistinguishable from the original."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=repo_resource(snapshot), description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
