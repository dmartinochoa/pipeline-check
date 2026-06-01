"""GCNET-001. Default VPC network exists in project."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="GCNET-001",
    title="Default VPC network exists in project",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-1188",),
    recommendation=(
        "Delete the default VPC network and create custom networks "
        "with explicitly defined subnets and firewall rules. The "
        "default network includes pre-populated firewall rules that "
        "allow broad internal traffic."
    ),
    docs_note=(
        "Every new GCP project is created with a default network that "
        "includes auto-created subnets in every region and permissive "
        "firewall rules (allow SSH, RDP, ICMP from anywhere). "
        "Deleting it forces teams to create purpose-built networks."
    ),
    exploit_example=(
        "A project keeps the auto-created default VPC network. The "
        "default network ships pre-populated firewall rules "
        "(default-allow-ssh, default-allow-rdp, default-allow-icmp) "
        "that permit ingress from 0.0.0.0/0, so every instance "
        "launched into it has SSH (22) and RDP (3389) reachable from "
        "the entire internet. An attacker scans the project's external "
        "IPs, finds the open ports, and brute-forces or exploits the "
        "exposed service to land on a VM, with no firewall change "
        "required."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    networks = catalog.compute_networks()
    resource = f"projects/{catalog.session.project_id}"
    has_default = any(
        nw.get("name") == "default"
        for nw in networks
    )
    if has_default:
        findings.append(Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=resource,
            description=(
                "The default VPC network still exists. It includes "
                "permissive auto-created firewall rules."
            ),
            recommendation=RULE.recommendation,
            passed=False,
        ))
    else:
        findings.append(Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=resource,
            description=(
                "No default VPC network found in the project."
            ),
            recommendation=RULE.recommendation,
            passed=True,
        ))
    return findings
