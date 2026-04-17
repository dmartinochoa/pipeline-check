"""IAM-001 — CI/CD service role has AdministratorAccess attached."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..._iam_policy import ADMIN_POLICY_ARN
from .._catalog import ResourceCatalog

RULE = Rule(
    id="IAM-001",
    title="CI/CD role has AdministratorAccess policy attached",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-269",),
    recommendation=(
        "Replace AdministratorAccess with least-privilege policies."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for role in catalog.cicd_roles():
        role_name = role.get("RoleName", "<unnamed>")
        arns, error = catalog.iam_role_attached_arns(role_name)
        if error:
            findings.append(Finding(
                check_id=RULE.id, title=RULE.title, severity=RULE.severity,
                resource=role_name,
                description=error,
                recommendation="Ensure iam:ListAttachedRolePolicies permission.",
                passed=False,
            ))
            continue
        has_admin = ADMIN_POLICY_ARN in arns
        desc = (
            f"Role '{role_name}' has AdministratorAccess attached."
            if has_admin else
            f"Role '{role_name}' does not have AdministratorAccess attached."
        )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=role_name, description=desc,
            recommendation=RULE.recommendation, passed=not has_admin,
        ))
    return findings
