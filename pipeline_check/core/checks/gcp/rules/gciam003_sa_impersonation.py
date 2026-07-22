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
    exploit_example=(
        "A CI service account is granted "
        "roles/iam.serviceAccountTokenCreator at the project level. An "
        "attacker who lands on that account (a leaked key, a poisoned "
        "build step) mints an access token for the project's most "
        "privileged service account and acts as it, turning a foothold "
        "in CI into full project control."
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
        expr = ""
        if isinstance(condition, dict):
            expr = str(condition.get("expression") or "")
        # Only a condition that references ``resource.name`` actually
        # narrows *which* service accounts can be impersonated; a
        # time-bound (``request.time``) or other non-resource expression
        # still permits impersonating every SA in the project.
        has_condition = bool(expr) and "resource.name" in expr
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
