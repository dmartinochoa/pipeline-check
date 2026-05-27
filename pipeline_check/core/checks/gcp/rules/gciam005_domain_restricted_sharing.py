"""GCIAM-005. Domain-restricted sharing constraint not enforced."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="GCIAM-005",
    title="Domain-restricted sharing constraint not enforced",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-284",),
    recommendation=(
        "Set the iam.allowedPolicyMemberDomains organization policy "
        "constraint to limit IAM bindings to your corporate domain(s). "
        "This prevents accidental or malicious grants to external "
        "accounts."
    ),
    docs_note=(
        "Without the domain-restricted sharing constraint, any GCP "
        "user with sufficient IAM permissions can grant access to "
        "arbitrary external Google accounts, enabling data exfiltration "
        "or persistence by outside parties."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    policies = catalog.org_policies()
    resource = f"projects/{catalog.session.project_id}"
    found = False
    for policy in policies:
        name = policy.get("name", "")
        if "iam.allowedPolicyMemberDomains" in name:
            found = True
            rules = policy.get("spec", {}).get("rules", [])
            if rules:
                findings.append(Finding(
                    check_id=RULE.id,
                    title=RULE.title,
                    severity=RULE.severity,
                    resource=resource,
                    description=(
                        "Domain-restricted sharing constraint "
                        "(iam.allowedPolicyMemberDomains) is configured."
                    ),
                    recommendation=RULE.recommendation,
                    passed=True,
                ))
            else:
                findings.append(Finding(
                    check_id=RULE.id,
                    title=RULE.title,
                    severity=RULE.severity,
                    resource=resource,
                    description=(
                        "Domain-restricted sharing constraint exists but "
                        "has no rules defined."
                    ),
                    recommendation=RULE.recommendation,
                    passed=False,
                ))
            break
    if not found:
        findings.append(Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=resource,
            description=(
                "No iam.allowedPolicyMemberDomains organization policy "
                "found. IAM bindings can be granted to any external "
                "Google account."
            ),
            recommendation=RULE.recommendation,
            passed=False,
        ))
    return findings
