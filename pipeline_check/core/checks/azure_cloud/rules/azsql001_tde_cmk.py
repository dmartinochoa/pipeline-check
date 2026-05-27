"""AZSQL-001. SQL Server TDE does not use a customer-managed key."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="AZSQL-001",
    title="SQL Server TDE does not use a customer-managed key",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-311",),
    recommendation=(
        "Configure Transparent Data Encryption (TDE) with a "
        "customer-managed key stored in Azure Key Vault. This gives "
        "you control over key rotation, revocation, and auditing."
    ),
    docs_note=(
        "By default, Azure SQL uses service-managed TDE keys. "
        "Customer-managed keys (CMK/BYOK) add a control plane: you "
        "can revoke the key to render the database unreadable, and "
        "key access events are logged in Key Vault diagnostics."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for entry in catalog.sql_servers():
        server = entry["server"]
        name = getattr(server, "name", "<unnamed>")
        # Check the server's key vault key (encryption protector).
        # The server object may expose encryption_protector or
        # we infer from the key_id property.
        key_id = getattr(server, "key_id", None)
        passed = key_id is not None and "vault.azure.net" in str(key_id).lower()
        if passed:
            desc = (
                f"SQL Server '{name}' uses a customer-managed TDE key "
                "from Key Vault."
            )
        else:
            desc = (
                f"SQL Server '{name}' uses service-managed TDE "
                "encryption. Customer-managed keys provide additional "
                "control over key lifecycle."
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
