"""ENTRA-001. Service principal assigned Global Administrator role."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="ENTRA-001",
    title="Service principal assigned Global Administrator",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-250",),
    recommendation=(
        "Replace the Global Administrator assignment with a scoped "
        "application role (Application Administrator, Cloud Application "
        "Administrator, or a custom role with least-privilege permissions). "
        "Service principals should never hold directory-wide admin rights."
    ),
    docs_note=(
        "Global Administrator is the highest-privilege directory role in "
        "Entra ID. A compromised service principal with this role can "
        "create users, reset passwords, modify conditional access, and "
        "escalate across the entire tenant."
    ),
    exploit_example=(
        "An attacker obtains the SP credential from a leaked CI variable, "
        "then uses the Global Administrator role to create a backdoor "
        "admin account, disable MFA policies, and persist across the "
        "tenant."
    ),
)

_GLOBAL_ADMIN_NAMES = frozenset({
    "global administrator",
    "company administrator",
})


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    assignments = catalog.role_assignments()
    role_defs = catalog.role_definitions()
    if not assignments:
        return findings

    for assignment in assignments:
        role_def_id = getattr(assignment, "role_definition_id", None)
        if not role_def_id:
            continue
        role_def = role_defs.get(role_def_id)
        if role_def is None:
            continue
        role_name = getattr(role_def, "role_name", "") or ""
        if role_name.lower() not in _GLOBAL_ADMIN_NAMES:
            continue
        principal_id = getattr(assignment, "principal_id", "<unknown>")
        principal_type = getattr(assignment, "principal_type", "")
        if principal_type and "ServicePrincipal" not in str(principal_type):
            continue
        findings.append(Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=principal_id,
            description=(
                f"Service principal {principal_id} is assigned the "
                f"'{role_name}' directory role. This grants unrestricted "
                "administrative access to the entire Entra ID tenant."
            ),
            recommendation=RULE.recommendation,
            passed=False,
        ))
    return findings
