"""SCM-007. Default branch protection allows force-pushes.

Maps to CIS Software Supply Chain Security Guide section 1.1.17
(ensure default branches' commits are protected) — a force-push
rewrites history, which destroys the audit trail any branch
protection rule depends on. Branch protection without force-push
denial is paper armor.
"""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import SCMRepoSnapshot, default_branch_name, repo_resource

RULE = Rule(
    id="SCM-007",
    title="Default branch protection allows force-pushes",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-1",),
    esf=("ESF-S-CHANGE-CONTROL",),
    cwe=("CWE-471",),
    recommendation=(
        "In the default-branch protection rule, set ``Allow force "
        "pushes`` to ``Disabled``. Force-pushes overwrite the audit "
        "trail; an attacker who lands a malicious commit can erase "
        "evidence of it after the fact. Also set ``Allow deletions`` "
        "to ``Disabled`` so the branch itself can't be wiped."
    ),
    docs_note=(
        "Reads ``allow_force_pushes.enabled`` from the branch "
        "protection payload. Fires when the value is True. The "
        "complementary deletion-protection knob is covered by a "
        "future SCM-NNN rule; this one focuses on the rewrite-history "
        "attack class because force-push is the primitive every "
        "post-incident rewrite uses to clean up after itself."
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
    fp = protection.get("allow_force_pushes")
    allowed = False
    if isinstance(fp, dict):
        allowed = bool(fp.get("enabled"))
    passed = not allowed
    desc = (
        f"Default branch ``{branch}`` blocks force-pushes."
        if passed else
        f"Default branch ``{branch}`` allows force-pushes. The "
        f"protection rule's review and status-check requirements are "
        f"defeated by a force-push that rewrites them away; an "
        f"attacker with write access can land a malicious commit, "
        f"force-push to remove it, and leave no audit trail."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=repo_resource(snapshot), description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
