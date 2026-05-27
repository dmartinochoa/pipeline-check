"""GCLOG-004. VPC Flow Logs not enabled on subnet."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="GCLOG-004",
    title="VPC Flow Logs not enabled on subnet",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-10",),
    cwe=("CWE-778",),
    recommendation=(
        "Enable VPC Flow Logs on all subnets. Flow logs capture "
        "a sample of network flows, enabling threat detection, "
        "traffic analysis, and compliance evidence."
    ),
    docs_note=(
        "VPC Flow Logs record a sample of network flows sent from "
        "and received by VM instances. Without them, lateral movement "
        "and data exfiltration over the network are invisible to "
        "security monitoring."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for subnet in catalog.compute_subnetworks():
        name = subnet.get("name", "<unnamed>")
        region = subnet.get("region", "")
        log_cfg = subnet.get("log_config", {})
        enabled = log_cfg.get("enable", False)
        resource = f"{name} ({region})" if region else name
        if enabled:
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=resource,
                description=(
                    f"Subnet '{name}' has VPC Flow Logs enabled."
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
                    f"Subnet '{name}' does not have VPC Flow Logs "
                    "enabled."
                ),
                recommendation=RULE.recommendation,
                passed=False,
            ))
    return findings
