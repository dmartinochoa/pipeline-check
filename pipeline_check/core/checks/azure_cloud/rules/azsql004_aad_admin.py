"""AZSQL-004. SQL Server has no Azure AD administrator configured."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="AZSQL-004",
    title="SQL Server has no Azure AD administrator configured",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-287",),
    recommendation=(
        "Configure an Azure AD administrator on the SQL Server. "
        "Azure AD authentication supports MFA, Conditional Access, "
        "and centralized identity management. Consider disabling "
        "SQL authentication entirely."
    ),
    docs_note=(
        "Without an Azure AD administrator, the SQL Server relies "
        "solely on SQL authentication (username/password). SQL "
        "credentials cannot be protected by MFA or Conditional "
        "Access policies."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for entry in catalog.sql_servers():
        server = entry["server"]
        ad_admin = entry.get("ad_admin")
        name = getattr(server, "name", "<unnamed>")
        passed = ad_admin is not None
        if passed:
            admin_login = getattr(ad_admin, "login", "<unknown>")
            desc = (
                f"SQL Server '{name}' has Azure AD administrator "
                f"'{admin_login}' configured."
            )
        else:
            desc = (
                f"SQL Server '{name}' has no Azure AD administrator "
                "configured. Authentication relies solely on SQL "
                "credentials."
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
