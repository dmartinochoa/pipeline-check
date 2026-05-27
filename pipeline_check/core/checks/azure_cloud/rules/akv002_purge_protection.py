"""AKV-002. Key Vault purge protection not enabled."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="AKV-002",
    title="Key Vault purge protection not enabled",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-404",),
    recommendation=(
        "Enable purge protection on the Key Vault. Purge protection "
        "prevents permanent deletion even by privileged administrators "
        "during the soft-delete retention period."
    ),
    docs_note=(
        "Soft delete alone allows a sufficiently privileged identity "
        "to purge a vault before the retention period expires. Purge "
        "protection makes the retention period mandatory, closing the "
        "insider-threat vector."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for vault in catalog.key_vaults():
        name = getattr(vault, "name", "<unnamed>")
        props = getattr(vault, "properties", None)
        purge_protection = getattr(props, "enable_purge_protection", None) if props else None
        passed = bool(purge_protection)
        if passed:
            desc = f"Key Vault '{name}' has purge protection enabled."
        else:
            desc = (
                f"Key Vault '{name}' does not have purge protection "
                "enabled. Privileged users can permanently purge the "
                "vault during the soft-delete retention window."
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
