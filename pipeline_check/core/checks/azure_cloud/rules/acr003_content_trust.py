"""ACR-003. Container registry content trust not enabled."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="ACR-003",
    title="Container registry content trust not enabled",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-494",),
    recommendation=(
        "Enable content trust on the container registry. Content "
        "trust uses Notary v2 to sign images, ensuring only signed "
        "images can be pulled."
    ),
    docs_note=(
        "Without content trust, any authenticated principal can push "
        "an image tag. An attacker who compromises push credentials "
        "can replace a production image with a malicious one."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for registry in catalog.container_registries():
        name = getattr(registry, "name", "<unnamed>")
        policies = getattr(registry, "policies", None)
        trust_policy = getattr(policies, "trust_policy", None) if policies else None
        trust_status = getattr(trust_policy, "status", "disabled") if trust_policy else "disabled"
        passed = str(trust_status).lower() == "enabled"
        if passed:
            desc = f"Container registry '{name}' has content trust enabled."
        else:
            desc = (
                f"Container registry '{name}' does not have content "
                "trust enabled. Unsigned images can be pushed and "
                "pulled."
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
