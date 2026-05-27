"""AKV-006. Key Vault uses vault access policies instead of RBAC."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="AKV-006",
    title="Key Vault uses vault access policies instead of RBAC",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-284",),
    recommendation=(
        "Enable RBAC authorization on the Key Vault. RBAC "
        "authorization uses Azure AD roles with fine-grained "
        "permissions and inherits Conditional Access policies, "
        "replacing the legacy vault access policy model."
    ),
    docs_note=(
        "Vault access policies are tenant-wide and do not support "
        "conditions, PIM activation, or Conditional Access. Migrating "
        "to RBAC aligns Key Vault access with the rest of the Azure "
        "control plane."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for vault in catalog.key_vaults():
        name = getattr(vault, "name", "<unnamed>")
        props = getattr(vault, "properties", None)
        rbac = getattr(props, "enable_rbac_authorization", None) if props else None
        passed = bool(rbac)
        if passed:
            desc = (
                f"Key Vault '{name}' uses Azure RBAC authorization."
            )
        else:
            desc = (
                f"Key Vault '{name}' uses legacy vault access policies "
                "instead of Azure RBAC authorization."
            )
        findings.append(Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=name,
            description=desc,
            recommendation=RULE.recommendation,
            passed=passed,
        ))
    return findings
