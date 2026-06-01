"""ENTRA-004. No Conditional Access policy requiring MFA for admins."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="ENTRA-004",
    title="No Conditional Access policy requiring MFA for admins",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-308",),
    recommendation=(
        "Create a Conditional Access policy that requires multi-factor "
        "authentication for all users assigned directory admin roles "
        "(Global Administrator, Privileged Role Administrator, etc.)."
    ),
    docs_note=(
        "Admin accounts are the highest-value targets in Entra ID. "
        "Without an MFA requirement enforced through Conditional "
        "Access, a single stolen password grants full tenant control."
    ),
    exploit_example=(
        "An attacker phishes a Global Administrator's password. "
        "Without a Conditional Access MFA policy, the attacker signs "
        "in directly, creates a backdoor admin account, and persists "
        "across the tenant."
    ),
)

_MFA_GRANT = "mfa"
_ADMIN_ROLE_IDS = frozenset({
    "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
    "e8611ab8-c189-46e8-94e1-60213ab1f814",  # Privileged Role Admin
    "194ae4cb-b126-40b2-bd5b-6091b380977d",  # Security Administrator
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",  # SharePoint Administrator
    "29232cdf-9323-42fd-ade2-1d097af3e4de",  # Exchange Administrator
    "fe930be7-5e62-47db-91af-98c3a49a38b1",  # User Administrator
})


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    policies = catalog.conditional_access_policies()
    resource = "Entra ID Conditional Access"

    mfa_for_admins = False
    for policy in policies:
        state = policy.get("state", "")
        if state != "enabled":
            continue
        grant = policy.get("grantControls") or {}
        # builtInControls is often present-but-null in the Graph response,
        # so `.get(key, [])` (default only on absent key) is not enough.
        built_in = [
            c.lower() for c in (grant.get("builtInControls") or [])
            if isinstance(c, str)
        ]
        # Modern policies enforce MFA via authenticationStrength rather
        # than the legacy builtInControls "mfa" grant; treat either as MFA.
        has_mfa = _MFA_GRANT in built_in or bool(grant.get("authenticationStrength"))
        if not has_mfa:
            continue
        conditions = policy.get("conditions") or {}
        users = conditions.get("users") or {}
        include_roles = users.get("includeRoles", [])
        include_users = users.get("includeUsers", [])
        if "All" in include_users:
            mfa_for_admins = True
            break
        if any(r in _ADMIN_ROLE_IDS for r in include_roles):
            mfa_for_admins = True
            break

    if mfa_for_admins:
        findings.append(Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=resource,
            description=(
                "At least one enabled Conditional Access policy "
                "requires MFA for admin roles."
            ),
            recommendation=RULE.recommendation,
            passed=True,
        ))
    else:
        findings.append(Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=resource,
            description=(
                "No enabled Conditional Access policy was found that "
                "requires MFA for directory admin roles. Admin accounts "
                "can sign in with a password alone."
            ),
            recommendation=RULE.recommendation,
            passed=False,
        ))
    return findings
