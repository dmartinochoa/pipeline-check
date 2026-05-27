"""GCCE-004. Compute instance has an external IP address."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="GCCE-004",
    title="Compute instance has an external IP address",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-284",),
    recommendation=(
        "Remove external IP addresses from instances that do not need "
        "direct internet access. Use Cloud NAT for outbound "
        "connectivity and IAP TCP forwarding for administrative "
        "access."
    ),
    docs_note=(
        "An external IP makes the instance directly addressable from "
        "the internet. Combined with a permissive firewall rule, this "
        "exposes the instance to scanning, brute-force attacks, and "
        "exploitation of any listening service."
    ),
    exploit_example=(
        "An attacker discovers an externally-addressed instance "
        "running an unpatched web server. They exploit a known CVE "
        "to gain shell access, then use the instance's service account "
        "token to access internal resources."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for inst in catalog.compute_instances():
        name = inst.get("name", "<unnamed>")
        interfaces = inst.get("network_interfaces", [])
        external_ips: list[str] = []
        for ni in interfaces:
            for ac in ni.get("access_configs", []):
                nat_ip = ac.get("nat_ip")
                if nat_ip:
                    external_ips.append(nat_ip)
                elif ac.get("type"):
                    external_ips.append("<ephemeral>")
        if external_ips:
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=name,
                description=(
                    f"Instance '{name}' has external IP(s): "
                    f"{', '.join(external_ips)}. It is directly "
                    "reachable from the internet."
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
                    f"Instance '{name}' has no external IP address."
                ),
                recommendation=RULE.recommendation,
                passed=True,
            ))
    return findings
