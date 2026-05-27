"""AZST-003. Storage account not encrypted with customer-managed key."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="AZST-003",
    title="Storage account not encrypted with customer-managed key",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-311",),
    recommendation=(
        "Configure the storage account to use a customer-managed key "
        "(CMK) stored in Azure Key Vault. This gives you control over "
        "key rotation and revocation."
    ),
    docs_note=(
        "Azure encrypts all storage data at rest by default with "
        "Microsoft-managed keys. Customer-managed keys add an "
        "additional control plane: you can revoke the key to render "
        "data unreadable, and key access is auditable via Key Vault "
        "diagnostic logs."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for account in catalog.storage_accounts():
        name = getattr(account, "name", "<unnamed>")
        encryption = getattr(account, "encryption", None)
        key_source = getattr(encryption, "key_source", "Microsoft.Storage") if encryption else "Microsoft.Storage"
        passed = str(key_source) != "Microsoft.Storage"
        if passed:
            desc = (
                f"Storage account '{name}' uses a customer-managed "
                "encryption key."
            )
        else:
            desc = (
                f"Storage account '{name}' uses Microsoft-managed "
                "encryption keys. Customer-managed keys provide "
                "additional control over key lifecycle and auditability."
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
