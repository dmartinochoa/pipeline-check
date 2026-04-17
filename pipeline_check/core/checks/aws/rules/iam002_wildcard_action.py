"""IAM-002 — CI/CD role has a wildcard Action in any attached policy."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..._iam_policy import has_wildcard_action
from .._catalog import ResourceCatalog

RULE = Rule(
    id="IAM-002",
    title="CI/CD role has wildcard Action in attached policy",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-269",),
    recommendation="Replace wildcard actions with specific IAM actions.",
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for role in catalog.cicd_roles():
        role_name = role.get("RoleName", "<unnamed>")
        docs, error = catalog.iam_role_policy_docs(role_name)
        offenders = [n for n, d in docs if has_wildcard_action(d)]
        passed = not offenders and error is None
        if error:
            desc = f"{error}. Cannot verify wildcard actions for '{role_name}'."
        elif offenders:
            desc = f"Policy/policies {offenders} on '{role_name}' use Action: '*'."
        else:
            desc = f"No policy on '{role_name}' uses Action: '*'."
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=role_name, description=desc,
            recommendation=RULE.recommendation, passed=passed,
        ))
    return findings
