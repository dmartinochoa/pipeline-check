"""AZMON-004. Key Vault has no diagnostic settings configured."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="AZMON-004",
    title="Key Vault has no diagnostic settings configured",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-10",),
    cwe=("CWE-778",),
    recommendation=(
        "Enable diagnostic settings on each Key Vault to send "
        "AuditEvent logs to a Log Analytics workspace. These logs "
        "record every secret read, key use, and access policy change."
    ),
    docs_note=(
        "Key Vault audit logs are the primary mechanism for detecting "
        "unauthorized secret access. Without diagnostic settings, "
        "access events are not retained beyond the Azure platform "
        "default and cannot be queried or alerted on."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for vault in catalog.key_vaults():
        name = getattr(vault, "name", "<unnamed>")
        vault_id = getattr(vault, "id", "")
        # Check if the vault has diagnostic settings configured.
        # We use the monitor client to list diagnostic settings
        # for the vault resource URI.
        has_diag = False
        if vault_id:
            try:
                from azure.mgmt.monitor import MonitorManagementClient
                client = catalog.mgmt_client(MonitorManagementClient)
                settings = list(
                    client.diagnostic_settings.list(
                        resource_uri=vault_id,
                    ),
                )
                has_diag = len(settings) > 0
            except Exception:
                pass

        passed = has_diag
        if passed:
            desc = (
                f"Key Vault '{name}' has diagnostic settings "
                "configured."
            )
        else:
            desc = (
                f"Key Vault '{name}' does not have diagnostic settings "
                "configured. Access events and audit logs are not "
                "forwarded to a monitoring sink."
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
