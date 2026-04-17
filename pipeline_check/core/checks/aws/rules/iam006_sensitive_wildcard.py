"""IAM-006 — Sensitive actions granted with wildcard Resource."""
from __future__ import annotations

from ..._iam_policy import sensitive_wildcard
from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="IAM-006",
    title="Sensitive actions granted with wildcard Resource",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-732",),
    recommendation=(
        "Scope the Resource element to specific ARNs (buckets, keys, "
        "secrets, roles)."
    ),
    docs_note=(
        "IAM-002 catches ``Action: \"*\"``. IAM-006 catches the more "
        "common \"scoped action, unscoped resource\" pattern on sensitive "
        "services (S3/KMS/SecretsManager/SSM/IAM/STS/DynamoDB/Lambda/EC2)."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for role in catalog.cicd_roles():
        role_name = role.get("RoleName", "<unnamed>")
        docs, error = catalog.iam_role_policy_docs(role_name)
        hits: dict[str, list[str]] = {}
        for name, doc in docs:
            sensitive = sensitive_wildcard(doc)
            if sensitive:
                hits[name] = sorted(set(sensitive))
        passed = not hits and error is None
        if error:
            desc = f"{error}. Cannot verify sensitive-action scoping for '{role_name}'."
        elif hits:
            pairs = ", ".join(f"{k}→{v}" for k, v in hits.items())
            desc = (
                f"Policy/policies on '{role_name}' grant sensitive actions over "
                f"Resource: '*': {pairs}."
            )
        else:
            desc = f"No policy on '{role_name}' pairs sensitive actions with Resource: '*'."
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=role_name, description=desc,
            recommendation=RULE.recommendation, passed=passed,
        ))
    return findings
