"""AZSQL-003. SQL Server allows public network access."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="AZSQL-003",
    title="SQL Server allows public network access",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-284",),
    recommendation=(
        "Disable public network access on the SQL Server and use "
        "private endpoints for connectivity. If public access is "
        "required temporarily, restrict firewall rules to specific "
        "IP ranges."
    ),
    docs_note=(
        "A SQL Server with public network access enabled exposes "
        "its TDS endpoint to the internet. Combined with weak "
        "authentication or a SQL injection vector, this provides "
        "a direct path to the database."
    ),
    exploit_example=(
        "An attacker discovers a publicly accessible SQL Server "
        "hosting a CI/CD state database. Using credentials leaked "
        "from a pipeline log, the attacker connects directly and "
        "exfiltrates pipeline secrets stored in the database."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for entry in catalog.sql_servers():
        server = entry["server"]
        name = getattr(server, "name", "<unnamed>")
        public_access = str(
            getattr(server, "public_network_access", "Enabled"),
        ).lower()
        passed = public_access == "disabled"
        if passed:
            desc = (
                f"SQL Server '{name}' has public network access "
                "disabled."
            )
        else:
            desc = (
                f"SQL Server '{name}' allows public network access. "
                "The server is reachable from the internet."
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
