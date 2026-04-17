"""IAM-003 — CI/CD role has no permissions boundary."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="IAM-003",
    title="CI/CD role has no permission boundary",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-732",),
    recommendation="Attach a permissions boundary defining max permissions.",
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for role in catalog.cicd_roles():
        role_name = role.get("RoleName", "<unnamed>")
        boundary = role.get("PermissionsBoundary", {}) or {}
        passed = bool(boundary.get("PermissionsBoundaryArn"))
        desc = (
            f"Role '{role_name}' has a permissions boundary: "
            f"{boundary.get('PermissionsBoundaryArn')}."
            if passed else
            f"Role '{role_name}' has no permissions boundary."
        )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=role_name, description=desc,
            recommendation=RULE.recommendation, passed=passed,
        ))
    return findings
