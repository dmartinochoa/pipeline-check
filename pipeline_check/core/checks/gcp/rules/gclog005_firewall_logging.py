"""GCLOG-005. Firewall rule logging not enabled."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="GCLOG-005",
    title="Firewall rule logging not enabled",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-10",),
    cwe=("CWE-778",),
    recommendation=(
        "Enable logging on all firewall rules. Firewall logs record "
        "connections allowed and denied by each rule, supporting "
        "incident investigation and compliance evidence."
    ),
    docs_note=(
        "Without firewall rule logging, allowed and denied connection "
        "attempts are invisible. Enabling logs on every rule creates "
        "an audit trail for traffic flowing through VPC firewalls."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for fw in catalog.compute_firewalls():
        name = fw.get("name", "<unnamed>")
        if fw.get("disabled"):
            continue
        log_cfg = fw.get("log_config", {})
        enabled = log_cfg.get("enable", False)
        if enabled:
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=name,
                description=(
                    f"Firewall rule '{name}' has logging enabled."
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
                    f"Firewall rule '{name}' does not have logging "
                    "enabled."
                ),
                recommendation=RULE.recommendation,
                passed=False,
            ))
    return findings
