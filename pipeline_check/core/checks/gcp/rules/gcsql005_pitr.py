"""GCSQL-005. Cloud SQL instance does not have point-in-time recovery enabled."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="GCSQL-005",
    title="Cloud SQL instance does not have point-in-time recovery enabled",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-693",),
    recommendation=(
        "Enable point-in-time recovery (PITR) on every Cloud SQL "
        "instance. PITR uses write-ahead logs to allow recovery to "
        "any point within the retention window, minimizing data loss."
    ),
    docs_note=(
        "Automated backups alone only allow recovery to the latest "
        "backup. Point-in-time recovery extends this to any second "
        "within the log retention window, reducing the recovery point "
        "objective (RPO) from hours to seconds."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for inst in catalog.cloud_sql_instances():
        name = inst.get("name", "<unnamed>")
        settings = inst.get("settings", {})
        backup_config = settings.get("backupConfiguration", {})
        pitr = backup_config.get("pointInTimeRecoveryEnabled", False)
        if pitr:
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=name,
                description=(
                    f"Cloud SQL instance '{name}' has point-in-time "
                    "recovery enabled."
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
                    "point-in-time recovery enabled."
                ),
                recommendation=RULE.recommendation,
                passed=False,
            ))
    return findings
