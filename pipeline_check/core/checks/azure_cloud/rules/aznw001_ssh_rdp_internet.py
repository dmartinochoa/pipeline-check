"""AZNW-001. NSG allows inbound SSH or RDP from the internet."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="AZNW-001",
    title="NSG allows inbound SSH or RDP from the internet",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-284",),
    recommendation=(
        "Remove or restrict NSG rules that allow inbound access on "
        "ports 22 (SSH) and 3389 (RDP) from any source. Use Azure "
        "Bastion, JIT VM access, or a VPN gateway for administrative "
        "access."
    ),
    docs_note=(
        "Unrestricted SSH and RDP from the internet are the top "
        "entry vector for compromised VMs. Automated scanners "
        "continuously probe these ports, and a weak or leaked "
        "credential grants immediate shell access."
    ),
    exploit_example=(
        "An attacker scans Azure IP ranges for port 22 open to the "
        "internet, finds a build agent VM, and brute-forces the SSH "
        "password. From the agent the attacker accesses pipeline "
        "secrets and pushes malicious code."
    ),
)

_DANGEROUS_PORTS = {22, 3389}
_ANY_SOURCES = {"*", "internet", "0.0.0.0/0", "any"}


def _port_in_range(port: int, range_str: str) -> bool:
    """Return True if *port* falls within a port range string."""
    range_str = str(range_str).strip()
    if range_str == "*":
        return True
    for part in range_str.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            try:
                if int(lo) <= port <= int(hi):
                    return True
            except ValueError:
                continue
        else:
            try:
                if int(part) == port:
                    return True
            except ValueError:
                continue
    return False


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for nsg in catalog.network_security_groups():
        nsg_name = getattr(nsg, "name", "<unnamed>")
        rules = getattr(nsg, "security_rules", []) or []
        flagged_ports: set[int] = set()
        for rule in rules:
            direction = str(getattr(rule, "direction", "")).lower()
            access = str(getattr(rule, "access", "")).lower()
            if direction != "inbound" or access != "allow":
                continue
            src = str(getattr(rule, "source_address_prefix", "")).lower()
            src_list = [
                s.lower()
                for s in (getattr(rule, "source_address_prefixes", []) or [])
            ]
            if src not in _ANY_SOURCES and not any(
                s in _ANY_SOURCES for s in src_list
            ):
                continue
            dest_port = str(
                getattr(rule, "destination_port_range", ""),
            )
            dest_ports = getattr(
                rule, "destination_port_ranges", [],
            ) or []
            all_ranges = [dest_port] + list(dest_ports)
            for port in _DANGEROUS_PORTS:
                for r in all_ranges:
                    if _port_in_range(port, r):
                        flagged_ports.add(port)

        if flagged_ports:
            port_labels = ", ".join(
                f"{p}/{'SSH' if p == 22 else 'RDP'}"
                for p in sorted(flagged_ports)
            )
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=nsg_name,
                description=(
                    f"NSG '{nsg_name}' allows inbound traffic on "
                    f"{port_labels} from the internet."
                ),
                recommendation=RULE.recommendation,
                passed=False,
            ))
        else:
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=nsg_name,
                description=(
                    f"NSG '{nsg_name}' does not allow unrestricted "
                    "inbound SSH or RDP from the internet."
                ),
                recommendation=RULE.recommendation,
                passed=True,
            ))
    return findings
