"""ENTRA-005. No Conditional Access policy restricting external/guest users."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="ENTRA-005",
    title="No Conditional Access policy restricting external users",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-284",),
    recommendation=(
        "Create a Conditional Access policy that restricts guest and "
        "external user access. Require MFA, limit session lifetime, "
        "or block access to sensitive applications for external "
        "identities."
    ),
    docs_note=(
        "External (B2B guest) users inherit broad default permissions "
        "in Entra ID unless Conditional Access policies explicitly "
        "limit them. A compromised partner account can enumerate "
        "directory objects and access shared applications."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    policies = catalog.conditional_access_policies()
    resource = "Entra ID Conditional Access"

    restricts_guests = False
    for policy in policies:
        state = policy.get("state", "")
        if state != "enabled":
            continue
        conditions = policy.get("conditions") or {}
        users = conditions.get("users") or {}
        include_guests = users.get("includeGuestsOrExternalUsers")
        include_users = users.get("includeUsers", [])
        if include_guests or "GuestsOrExternalUsers" in include_users:
            restricts_guests = True
            break

    if restricts_guests:
        findings.append(Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=resource,
            description=(
                "At least one enabled Conditional Access policy targets "
                "guest or external users."
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
                "No enabled Conditional Access policy restricts guest "
                "or external user access. External identities use the "
                "same default access policies as internal users."
            ),
            recommendation=RULE.recommendation,
            passed=False,
        ))
    return findings
