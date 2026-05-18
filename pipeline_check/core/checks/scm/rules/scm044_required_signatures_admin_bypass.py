"""SCM-044. Required signed-commits is bypassed for administrators.

The default-branch protection rule's ``required_signatures.enabled``
flag is gated by ``enforce_admins.enabled``: when admins aren't
subject to the protection, an admin (or a stolen admin PAT) can
push unsigned commits to the protected branch despite the policy.
SCM-006 only checks that the signature requirement exists; this
rule catches the silent-bypass case.

Distinct from SCM-010 (generic admin-bypass), which covers all
protection rules at once for change-control review. SCM-044 is the
narrower cryptographic-signing-specific failure: review can be
re-checked by a human after the fact, but an unsigned commit's
authorship can't be cryptographically attributed once it's landed.
"""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import (
    SCMRepoSnapshot,
    default_branch_name,
    repo_resource,
)

RULE = Rule(
    id="SCM-044",
    title="Default-branch signed-commits requirement bypassed for admins",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-1", "CICD-SEC-6"),
    esf=("ESF-S-CHANGE-CONTROL",),
    cwe=("CWE-345",),
    recommendation=(
        "Enable ``Include administrators`` (``enforce_admins``) on "
        "the default-branch protection rule so the signed-commit "
        "requirement applies to admins too. Alternatively, migrate "
        "the requirement into a repository ruleset where bypass "
        "actors are explicit and auditable — admin bypass via the "
        "legacy protection knob is implicit, while a ruleset bypass "
        "list names each actor and is visible in the audit log "
        "(see SCM-030 for the ruleset-side bypass check)."
    ),
    docs_note=(
        "Fires when ``required_signatures.enabled == True`` and "
        "``enforce_admins.enabled`` is missing or ``False``. The "
        "rule passes silently in two cases: when signed commits "
        "aren't required at all (SCM-006 owns that surface) and "
        "when branch protection is missing entirely (SCM-001)."
    ),
    known_fp=(
        "Solo-maintainer repos where the single admin is also the "
        "only signing-key holder may turn off enforce_admins to "
        "self-recover from a lost key. Suppress per repo with a "
        "rationale that names the recovery workflow.",
    ),
)


def _is_enabled(payload: Any) -> bool:
    if isinstance(payload, dict):
        return bool(payload.get("enabled"))
    return False


def check(snapshot: SCMRepoSnapshot) -> Finding:
    branch = default_branch_name(snapshot)
    protection = snapshot.default_branch_protection
    if not isinstance(protection, dict):
        # SCM-001 owns the no-protection case.
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                f"Default branch ``{branch}`` has no protection rule "
                f"to evaluate. See SCM-001."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    if not _is_enabled(protection.get("required_signatures")):
        # SCM-006 owns the no-signature case.
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                f"Default branch ``{branch}`` does not require "
                f"signed commits; SCM-006 owns that case."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    passed = _is_enabled(protection.get("enforce_admins"))
    desc = (
        f"Default branch ``{branch}`` requires signed commits and "
        f"enforces the requirement on administrators."
        if passed else
        f"Default branch ``{branch}`` requires signed commits but "
        f"``enforce_admins`` is disabled. An admin (or a stolen "
        f"admin PAT) can push unsigned commits despite the policy, "
        f"leaving no cryptographic attribution for the commits "
        f"that landed."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=repo_resource(snapshot), description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
