"""GCIAM-003. Service account token creator granted without constraint."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="GCIAM-003",
    title="Service account token creator granted without constraint",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-284",),
    recommendation=(
        "Restrict iam.serviceAccountTokenCreator bindings to specific "
        "service accounts using IAM conditions "
        "(resource.name == 'projects/-/serviceAccounts/TARGET'). "
        "Avoid project-level grants of this role."
    ),
    docs_note=(
        "roles/iam.serviceAccountTokenCreator allows a principal to "
        "mint OAuth2 tokens and sign JWTs as any service account in "
        "the project. A project-level grant without a condition is "
        "effectively a privilege-escalation vector."
    ),
)

_IMPERSONATION_ROLES = frozenset({
    "roles/iam.serviceAccountTokenCreator",
    "roles/iam.serviceAccountUser",
})


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    policy = catalog.project_iam_policy()
    if not policy:
        return findings
    for binding in policy.get("bindings", []):
        role = binding.get("role", "")
        if role not in _IMPERSONATION_ROLES:
            continue
        condition = binding.get("condition")
        has_condition = bool(condition and condition.get("expression"))
        for member in binding.get("members", []):
            if has_condition:
                findings.append(Finding(
                    check_id=RULE.id,
                    title=RULE.title,
                    severity=RULE.severity,
                    resource=member,
                    description=(
                        f"'{member}' has '{role}' with an IAM "
                        "condition restricting scope."
                    ),
                    recommendation=RULE.recommendation,
                    passed=True,
                ))
            else:
                findings.append(Finding(
                    check_id=RULE.id,
                    title=RULE.title,
                    severity=RULE.severity,
                    resource=member,
                    description=(
                        f"'{member}' has '{role}' at the project "
                        "level without an IAM condition. This allows "
                        "impersonation of any service account in the "
                        "project."
                    ),
                    recommendation=RULE.recommendation,
                    passed=False,
                ))
    return findings
