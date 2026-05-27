"""AZVM-002. Virtual machine has a public IP address."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="AZVM-002",
    title="Virtual machine has a public IP address",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-284",),
    recommendation=(
        "Remove public IP addresses from VM network interfaces. "
        "Use Azure Bastion for administrative access and private "
        "endpoints or internal load balancers for service traffic."
    ),
    docs_note=(
        "VMs with public IP addresses are directly reachable from "
        "the internet. Build agents, pipeline controllers, and "
        "other CI/CD infrastructure should operate on private "
        "networks only."
    ),
    exploit_example=(
        "A CI build agent VM with a public IP is discovered during "
        "a port scan. The attacker exploits an unpatched service "
        "on the agent and gains access to the pipeline "
        "environment."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    # Build a set of NIC IDs that have public IPs.
    public_ips = catalog.public_ip_addresses()
    nics_with_public_ip: set[str] = set()
    for pip in public_ips:
        ip_config = getattr(pip, "ip_configuration", None)
        config_id = str(getattr(ip_config, "id", "")).lower() if ip_config else ""
        if "/networkinterfaces/" in config_id:
            # Extract the NIC resource ID (everything up to /ipConfigurations).
            nic_id = config_id.split("/ipconfigurations/")[0]
            nics_with_public_ip.add(nic_id)

    for vm in catalog.virtual_machines():
        name = getattr(vm, "name", "<unnamed>")
        network_profile = getattr(vm, "network_profile", None)
        nic_refs = getattr(network_profile, "network_interfaces", []) if network_profile else []
        has_public = False
        for nic_ref in nic_refs or []:
            nic_id = str(getattr(nic_ref, "id", "")).lower()
            if nic_id in nics_with_public_ip:
                has_public = True
                break

        passed = not has_public
        if passed:
            desc = (
                f"VM '{name}' has no public IP address on its "
                "network interfaces."
            )
        else:
            desc = (
                f"VM '{name}' has a public IP address associated with "
                "a network interface. The VM is directly reachable "
                "from the internet."
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
