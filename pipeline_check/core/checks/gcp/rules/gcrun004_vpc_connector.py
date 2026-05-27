"""GCRUN-004. Cloud Run service does not use a VPC connector."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="GCRUN-004",
    title="Cloud Run service does not use a VPC connector",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-284",),
    recommendation=(
        "Configure a Serverless VPC Access connector on Cloud Run "
        "services that access internal resources. This routes "
        "egress traffic through the VPC, enabling private IP "
        "connectivity and firewall enforcement."
    ),
    docs_note=(
        "Without a VPC connector, Cloud Run services route egress "
        "traffic through the public internet. Services that access "
        "databases, caches, or internal APIs over the internet "
        "increase their attack surface."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for svc in catalog.cloud_run_services():
        name = svc.get("name", "<unnamed>")
        template = svc.get("template", {})
        vpc_access = template.get("vpc_access", {})
        connector = vpc_access.get("connector", "")
        if connector:
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=name,
                description=(
                    f"Cloud Run service '{name}' uses VPC connector: "
                    f"{connector}."
                ),
                recommendation=RULE.recommendation,
                passed=True,
            ))
        else:
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=name,
                description=(
                    f"Cloud Run service '{name}' does not use a VPC "
                    "connector. Egress traffic routes through the "
                    "public internet."
                ),
                recommendation=RULE.recommendation,
                passed=False,
            ))
    return findings
