"""GCNET-005. No Cloud NAT gateway configured."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="GCNET-005",
    title="No Cloud NAT gateway configured",
    severity=Severity.LOW,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-284",),
    recommendation=(
        "Configure a Cloud NAT gateway on at least one Cloud Router "
        "so that instances without external IPs can reach the internet "
        "for updates and package downloads without being directly "
        "addressable."
    ),
    docs_note=(
        "Cloud NAT provides outbound internet connectivity for "
        "instances without external IPs. Without it, private instances "
        "are cut off from external repositories, update servers, and "
        "third-party APIs unless a proxy is configured."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    routers = catalog.compute_routers()
    resource = f"projects/{catalog.session.project_id}"
    has_nat = any(
        len(r.get("nats", [])) > 0
        for r in routers
    )
    if has_nat:
        findings.append(Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=resource,
            description=(
                "At least one Cloud NAT gateway is configured."
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
                "No Cloud NAT gateway found. Private instances "
                "cannot reach the internet for updates."
            ),
            recommendation=RULE.recommendation,
            passed=False,
        ))
    return findings
