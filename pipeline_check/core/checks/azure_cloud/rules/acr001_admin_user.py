"""ACR-001. Container registry admin user enabled."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="ACR-001",
    title="Container registry admin user enabled",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-250",),
    recommendation=(
        "Disable the admin user on the container registry and use "
        "Azure AD-based authentication (managed identities, service "
        "principals, or repository-scoped tokens) instead."
    ),
    docs_note=(
        "The ACR admin user is a single shared credential with full "
        "push/pull/delete access. It cannot be scoped, audited per "
        "identity, or protected with conditional access."
    ),
    exploit_example=(
        "The admin credential is stored in a pipeline variable. An "
        "attacker extracts it and pushes a trojanized image that the "
        "deployment pipeline pulls on the next release."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for registry in catalog.container_registries():
        name = getattr(registry, "name", "<unnamed>")
        admin_enabled = getattr(registry, "admin_user_enabled", False)
        passed = not admin_enabled
        if passed:
            desc = f"Container registry '{name}' has the admin user disabled."
        else:
            desc = (
                f"Container registry '{name}' has the admin user "
                "enabled. The admin credential is a shared, "
                "unscoped push/pull token."
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
