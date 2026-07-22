"""GCSQL-004. Cloud SQL instance does not have IAM authentication enabled."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="GCSQL-004",
    title="Cloud SQL instance does not have IAM authentication enabled",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-287",),
    recommendation=(
        "Enable IAM database authentication by setting the "
        "cloudsql.iam_authentication database flag to 'on'. This "
        "allows using IAM-managed identities instead of built-in "
        "database passwords."
    ),
    docs_note=(
        "IAM database authentication ties database access to "
        "centrally managed IAM identities. Without it, database "
        "credentials are managed separately, increasing the risk "
        "of stale or shared passwords."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for inst in catalog.cloud_sql_instances():
        name = inst.get("name", "<unnamed>")
        # IAM database authentication is available for MySQL and
        # PostgreSQL only; SQL Server has no such flag, so flagging it is
        # an unactionable false positive. Skip those engines.
        if str(inst.get("databaseVersion", "")).upper().startswith("SQLSERVER"):
            continue
        settings = inst.get("settings", {})
        flags = settings.get("databaseFlags", [])
        iam_auth = False
        for flag in flags:
            if (
                flag.get("name") == "cloudsql.iam_authentication"
                and flag.get("value") == "on"
            ):
                iam_auth = True
                break
        if iam_auth:
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=name,
                description=(
                    f"Cloud SQL instance '{name}' has IAM database "
                    "authentication enabled."
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
                    f"Cloud SQL instance '{name}' does not have IAM "
                    "database authentication enabled."
                ),
                recommendation=RULE.recommendation,
                passed=False,
            ))
    return findings
