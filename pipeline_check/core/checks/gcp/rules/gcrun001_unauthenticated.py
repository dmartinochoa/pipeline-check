"""GCRUN-001. Cloud Run service allows unauthenticated access."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="GCRUN-001",
    title="Cloud Run service allows unauthenticated access",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-284",),
    recommendation=(
        "Set the Cloud Run service ingress to "
        "INGRESS_TRAFFIC_INTERNAL_ONLY or "
        "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER, or require "
        "authentication via IAM invoker bindings. Public services "
        "should be behind a load balancer with IAP or API Gateway."
    ),
    docs_note=(
        "A Cloud Run service with INGRESS_TRAFFIC_ALL allows any "
        "internet user to invoke it. If the service does not "
        "implement its own authentication, it is fully exposed."
    ),
    exploit_example=(
        "An attacker discovers a Cloud Run service URL that accepts "
        "all ingress traffic. The service has no authentication and "
        "exposes an internal admin API, allowing the attacker to "
        "read and modify application data."
    ),
)

_UNRESTRICTED_INGRESS = frozenset({
    "INGRESS_TRAFFIC_ALL",
})


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for svc in catalog.cloud_run_services():
        name = svc.get("name", "<unnamed>")
        ingress = svc.get("ingress", "INGRESS_TRAFFIC_ALL")
        if ingress in _UNRESTRICTED_INGRESS:
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=name,
                description=(
                    f"Cloud Run service '{name}' allows all ingress "
                    f"traffic (ingress={ingress}). It is publicly "
                    "accessible."
                ),
                recommendation=RULE.recommendation,
                passed=False,
            ))
        else:
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=name,
                description=(
                    f"Cloud Run service '{name}' restricts ingress "
                    f"(ingress={ingress})."
                ),
                recommendation=RULE.recommendation,
                passed=True,
            ))
    return findings
