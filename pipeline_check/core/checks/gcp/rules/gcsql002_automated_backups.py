"""GCSQL-002. Cloud SQL instance does not have automated backups enabled."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="GCSQL-002",
    title="Cloud SQL instance does not have automated backups enabled",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-693",),
    recommendation=(
        "Enable automated backups on every Cloud SQL instance. "
        "Automated backups protect against data loss from accidental "
        "deletion, corruption, or ransomware."
    ),
    docs_note=(
        "Without automated backups, a destructive action (accidental "
        "DROP TABLE, ransomware, or a rogue admin) can cause "
        "permanent data loss. Automated backups provide a recovery "
        "point within the configured retention window."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for inst in catalog.cloud_sql_instances():
        name = inst.get("name", "<unnamed>")
        settings = inst.get("settings", {})
        backup_config = settings.get("backupConfiguration", {})
        enabled = backup_config.get("enabled", False)
        if enabled:
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=name,
                description=(
                    f"Cloud SQL instance '{name}' has automated "
                    "backups enabled."
                ),
                recommendation=RULE.recommendation,
                passed=True,
            ))
        else:
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=name,
                description=(
                    f"Cloud SQL instance '{name}' does not have "
                    "automated backups enabled."
                ),
                recommendation=RULE.recommendation,
                passed=False,
            ))
    return findings
