"""IAM-004 — CI/CD role grants iam:PassRole with Resource:'*'."""
from __future__ import annotations

from ..._iam_policy import passrole_wildcard
from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="IAM-004",
    title="CI/CD role can PassRole to any role",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-269",),
    recommendation=(
        "Restrict iam:PassRole to specific role ARNs and add an "
        "iam:PassedToService condition."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for role in catalog.cicd_roles():
        role_name = role.get("RoleName", "<unnamed>")
        docs, error = catalog.iam_role_policy_docs(role_name)
        offenders = [n for n, d in docs if passrole_wildcard(d)]
        passed = not offenders and error is None
        if error:
            desc = f"{error}. Cannot verify iam:PassRole scope for '{role_name}'."
        elif offenders:
            desc = (
                f"Policy/policies {offenders} grant iam:PassRole with Resource: '*' — "
                f"a classic privilege-escalation path."
            )
        else:
            desc = f"No policy on '{role_name}' grants iam:PassRole with Resource: '*'."
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=role_name, description=desc,
            recommendation=RULE.recommendation, passed=passed,
        ))
    return findings
