"""GCNET-004. Subnet does not have Private Google Access enabled."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="GCNET-004",
    title="Subnet does not have Private Google Access enabled",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-319",),
    recommendation=(
        "Enable Private Google Access on all subnets so that instances "
        "without external IPs can still reach Google APIs and services "
        "over Google's internal network."
    ),
    docs_note=(
        "Without Private Google Access, instances that lack an "
        "external IP cannot reach Google APIs (Cloud Storage, "
        "BigQuery, etc.). Enabling it lets private instances access "
        "these services without exposing them to the internet."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for subnet in catalog.compute_subnetworks():
        name = subnet.get("name", "<unnamed>")
        region = subnet.get("region", "")
        enabled = subnet.get("private_ip_google_access", False)
        resource = f"{name} ({region})" if region else name
        if enabled:
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=resource,
                description=(
                    f"Subnet '{name}' has Private Google Access enabled."
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
                    f"Subnet '{name}' does not have Private Google "
                    "Access enabled. Instances without external IPs "
                    "cannot reach Google APIs."
                ),
                recommendation=RULE.recommendation,
                passed=False,
            ))
    return findings
