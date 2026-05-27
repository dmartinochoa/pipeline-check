"""GCSQL-001. Cloud SQL instance has a public IP address."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="GCSQL-001",
    title="Cloud SQL instance has a public IP address",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-284",),
    recommendation=(
        "Disable the public IP on the Cloud SQL instance and use "
        "private IP with VPC peering or the Cloud SQL Auth Proxy "
        "for connectivity. If a public IP is required, restrict "
        "authorized networks to specific CIDR ranges."
    ),
    docs_note=(
        "A Cloud SQL instance with a public IP is directly reachable "
        "from the internet. Even with authorized networks configured, "
        "the attack surface is larger than a private-IP-only setup "
        "behind a VPC."
    ),
    exploit_example=(
        "An attacker scans public IPs for MySQL/PostgreSQL ports, "
        "finds a Cloud SQL instance with a weak password, and "
        "exfiltrates the entire database."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for inst in catalog.cloud_sql_instances():
        name = inst.get("name", "<unnamed>")
        settings = inst.get("settings", {})
        ip_config = settings.get("ipConfiguration", {})
        ipv4_enabled = ip_config.get("ipv4Enabled", False)
        if ipv4_enabled:
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=name,
                description=(
                    f"Cloud SQL instance '{name}' has a public IPv4 "
                    "address enabled."
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
                    f"Cloud SQL instance '{name}' does not have a "
                    "public IP address."
                ),
                recommendation=RULE.recommendation,
                passed=True,
            ))
    return findings
