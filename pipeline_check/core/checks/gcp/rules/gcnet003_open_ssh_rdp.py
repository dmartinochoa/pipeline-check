"""GCNET-003. Firewall allows SSH or RDP from the internet."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="GCNET-003",
    title="Firewall allows SSH or RDP from the internet",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-284",),
    recommendation=(
        "Restrict SSH (tcp:22) and RDP (tcp:3389) firewall rules to "
        "specific source CIDR ranges (e.g. corporate VPN IPs). Use "
        "IAP TCP forwarding or OS Login instead of direct internet "
        "access."
    ),
    docs_note=(
        "Firewall rules allowing SSH or RDP from 0.0.0.0/0 expose "
        "instances to brute-force attacks and credential-stuffing "
        "from the entire internet. This is the most common initial "
        "access vector for cloud-hosted VMs."
    ),
    exploit_example=(
        "An attacker scans 0.0.0.0/0 for port 22, finds an instance "
        "with a weak SSH key, and gains shell access. From there they "
        "query the metadata server for service account tokens and "
        "pivot across the project."
    ),
)

_DANGEROUS_PORTS = frozenset({"22", "3389"})


def _allows_dangerous_port(allowed_list: list[dict[str, object]]) -> list[str]:
    """Return dangerous ports found in the allowed list."""
    found: list[str] = []
    for entry in allowed_list:
        protocol = str(entry.get("protocol", "")).lower()
        if protocol not in ("tcp", "all"):
            continue
        raw_ports = entry.get("ports")
        ports: list[object] = list(raw_ports) if isinstance(raw_ports, (list, tuple)) else []
        # An allowed entry with no ``ports`` list means *every* port of
        # that protocol. For ``tcp`` (and ``all``) that includes 22 and
        # 3389 — treating empty ports as all-ports only for ``all`` let a
        # ``tcp``-with-no-ports rule pass with a wrong "not on SSH or RDP
        # ports" note.
        if not ports:
            found.extend(sorted(_DANGEROUS_PORTS))
            continue
        for port_spec in ports:
            port_str = str(port_spec)
            if port_str in _DANGEROUS_PORTS:
                found.append(port_str)
            elif "-" in port_str:
                parts = port_str.split("-", 1)
                try:
                    lo, hi = int(parts[0]), int(parts[1])
                    for dp in _DANGEROUS_PORTS:
                        if lo <= int(dp) <= hi:
                            found.append(dp)
                except (ValueError, IndexError):
                    pass
    return found


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for fw in catalog.compute_firewalls():
        name = fw.get("name", "<unnamed>")
        if fw.get("disabled"):
            continue
        if fw.get("direction", "") != "INGRESS":
            continue
        source_ranges = fw.get("source_ranges", [])
        if "0.0.0.0/0" not in source_ranges:
            continue
        allowed = fw.get("allowed", [])
        dangerous = _allows_dangerous_port(allowed)
        if dangerous:
            port_label = ", ".join(
                f"tcp:{p}" for p in sorted(set(dangerous))
            )
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=name,
                description=(
                    f"Firewall rule '{name}' allows {port_label} "
                    "from 0.0.0.0/0 (the entire internet)."
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
                    f"Firewall rule '{name}' allows traffic from "
                    "0.0.0.0/0 but not on SSH or RDP ports."
                ),
                recommendation=RULE.recommendation,
                passed=True,
            ))
    return findings
