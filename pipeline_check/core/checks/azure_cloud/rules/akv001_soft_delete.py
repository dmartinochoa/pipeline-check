"""AKV-001. Key Vault soft delete not enabled."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="AKV-001",
    title="Key Vault soft delete not enabled",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-404",),
    recommendation=(
        "Enable soft delete on the Key Vault. As of Azure API version "
        "2021-06-01-preview, soft delete is enforced on new vaults. "
        "For older vaults, enable it via the portal or CLI."
    ),
    docs_note=(
        "Without soft delete, a deleted Key Vault (and all its keys, "
        "secrets, and certificates) is permanently lost. Soft delete "
        "retains the vault for a configurable retention period, "
        "enabling recovery from accidental or malicious deletion."
    ),
    exploit_example=(
        "An attacker with Contributor access deletes a Key Vault "
        "holding pipeline signing keys. Without soft delete, the keys "
        "are irrecoverable and the CI/CD pipeline's code-signing "
        "chain is broken."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for vault in catalog.key_vaults():
        name = getattr(vault, "name", "<unnamed>")
        props = getattr(vault, "properties", None)
        soft_delete = getattr(props, "enable_soft_delete", None) if props else None
        if soft_delete is None:
            soft_delete = True
        passed = bool(soft_delete)
        if passed:
            desc = f"Key Vault '{name}' has soft delete enabled."
        else:
            desc = (
                f"Key Vault '{name}' does not have soft delete enabled. "
                "Deleted keys, secrets, and certificates are permanently "
                "lost."
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
