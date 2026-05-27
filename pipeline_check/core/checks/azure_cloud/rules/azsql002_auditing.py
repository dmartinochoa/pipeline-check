"""AZSQL-002. SQL Server auditing not enabled."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="AZSQL-002",
    title="SQL Server auditing not enabled",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-10",),
    cwe=("CWE-778",),
    recommendation=(
        "Enable blob auditing on the SQL Server. Send audit logs to "
        "a Storage account and optionally to a Log Analytics "
        "workspace. Auditing records all database events including "
        "login attempts, queries, and schema changes."
    ),
    docs_note=(
        "Without auditing, database operations go unrecorded. "
        "Incident response teams cannot determine what data was "
        "accessed or modified after a breach."
    ),
    exploit_example=(
        "An attacker gains database access through a SQL injection "
        "in a pipeline management tool. Without auditing, the "
        "attacker's queries (credential extraction, data exfiltration) "
        "leave no trace."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for entry in catalog.sql_servers():
        server = entry["server"]
        auditing = entry.get("auditing")
        name = getattr(server, "name", "<unnamed>")
        state = str(getattr(auditing, "state", "Disabled")).lower() if auditing else "disabled"
        passed = state == "enabled"
        if passed:
            desc = (
                f"SQL Server '{name}' has blob auditing enabled."
            )
        else:
            desc = (
                f"SQL Server '{name}' does not have auditing enabled. "
                "Database events are not recorded."
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
