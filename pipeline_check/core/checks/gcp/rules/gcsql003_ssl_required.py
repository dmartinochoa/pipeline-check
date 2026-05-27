"""GCSQL-003. Cloud SQL instance does not require SSL connections."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="GCSQL-003",
    title="Cloud SQL instance does not require SSL connections",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-319",),
    recommendation=(
        "Set requireSsl to true in the Cloud SQL instance's "
        "ipConfiguration. This ensures all client connections are "
        "encrypted with TLS."
    ),
    docs_note=(
        "Without SSL enforcement, database connections can be "
        "intercepted on the network. An attacker with network access "
        "can capture credentials and query results in plaintext."
    ),
    exploit_example=(
        "An attacker performs a man-in-the-middle attack on the "
        "network between an application and its Cloud SQL instance. "
        "Without SSL enforcement, they capture database credentials "
        "and sensitive query results in plaintext."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for inst in catalog.cloud_sql_instances():
        name = inst.get("name", "<unnamed>")
        settings = inst.get("settings", {})
        ip_config = settings.get("ipConfiguration", {})
        require_ssl = ip_config.get("requireSsl", False)
        if require_ssl:
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=name,
                description=(
                    f"Cloud SQL instance '{name}' requires SSL for "
                    "all connections."
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
                    f"Cloud SQL instance '{name}' does not require "
                    "SSL. Connections may be unencrypted."
                ),
                recommendation=RULE.recommendation,
                passed=False,
            ))
    return findings
