"""AZSQL-005. SQL Server advanced threat protection not enabled."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="AZSQL-005",
    title="SQL Server advanced threat protection not enabled",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-10",),
    cwe=("CWE-693",),
    recommendation=(
        "Enable Advanced Threat Protection (ATP) on the SQL Server. "
        "ATP detects anomalous activities indicating potential SQL "
        "injection, brute-force attacks, and data exfiltration."
    ),
    docs_note=(
        "Advanced Threat Protection provides behavioral analytics "
        "on database activity. Without it, SQL injection attempts "
        "and credential stuffing attacks are not detected in real "
        "time."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for entry in catalog.sql_servers():
        server = entry["server"]
        threat = entry.get("threat_detection")
        name = getattr(server, "name", "<unnamed>")
        state = str(getattr(threat, "state", "Disabled")).lower() if threat else "disabled"
        passed = state == "enabled"
        if passed:
            desc = (
                f"SQL Server '{name}' has Advanced Threat Protection "
                "enabled."
            )
        else:
            desc = (
                f"SQL Server '{name}' does not have Advanced Threat "
                "Protection enabled. SQL injection and brute-force "
                "attacks are not detected."
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
