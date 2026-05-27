"""AZNW-005. Public IP address associated with a VM NIC."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="AZNW-005",
    title="Public IP address associated with a VM NIC",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-284",),
    recommendation=(
        "Remove public IP addresses from VM network interfaces. Use "
        "Azure Bastion, a load balancer, or a VPN/ExpressRoute "
        "gateway for inbound connectivity. For outbound traffic, "
        "use NAT Gateway."
    ),
    docs_note=(
        "A public IP on a VM NIC exposes the VM directly to the "
        "internet. Combined with a permissive NSG, this creates a "
        "direct attack path to build agents and pipeline "
        "infrastructure."
    ),
    exploit_example=(
        "A CI/CD build agent VM has a public IP. An attacker "
        "discovers the IP, exploits a known vulnerability in the "
        "agent software, and gains shell access to the build "
        "environment where pipeline secrets are available."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    public_ips = catalog.public_ip_addresses()

    for pip in public_ips:
        pip_name = getattr(pip, "name", "<unnamed>")
        ip_config = getattr(pip, "ip_configuration", None)
        config_id = str(getattr(ip_config, "id", "")).lower() if ip_config else ""
        # A public IP is associated with a VM NIC if its
        # ip_configuration ID contains /networkInterfaces/.
        is_vm_nic = "/networkinterfaces/" in config_id
        if not is_vm_nic:
            continue

        # Extract the NIC name from the resource ID.
        parts = config_id.split("/")
        nic_name = "<unknown>"
        for i, part in enumerate(parts):
            if part == "networkinterfaces" and i + 1 < len(parts):
                nic_name = parts[i + 1]
                break

        findings.append(Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=pip_name,
            description=(
                f"Public IP '{pip_name}' is associated with VM NIC "
                f"'{nic_name}'. The VM is directly reachable from the "
                "internet."
            ),
            recommendation=RULE.recommendation,
            passed=False,
        ))

    if not any(not f.passed for f in findings):
        findings.append(Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource="subscription",
            description=(
                "No public IP addresses are associated with VM "
                "network interfaces."
            ),
            recommendation=RULE.recommendation,
            passed=True,
        ))
    return findings
