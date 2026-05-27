"""GCLOG-008. No log metric filter for firewall rule changes."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="GCLOG-008",
    title="No log metric filter for firewall rule changes",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-10",),
    cwe=("CWE-778",),
    recommendation=(
        "Create a log-based metric with a filter matching firewall "
        "rule changes (e.g. resource.type=\"gce_firewall_rule\") and "
        "configure an alerting policy on it."
    ),
    docs_note=(
        "Firewall rule changes can open unexpected ingress paths. "
        "A log-based metric and alert for firewall mutations catches "
        "accidental or malicious network policy changes in real time."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    metrics = catalog.log_metrics()
    resource = f"projects/{catalog.session.project_id}"
    found = any(
        "gce_firewall_rule" in m.get("filter", "")
        for m in metrics
    )
    if found:
        findings.append(Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=resource,
            description=(
                "A log-based metric filter for firewall rule changes "
                "(gce_firewall_rule) exists."
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
                "No log-based metric filter found for firewall rule "
                "changes. Firewall mutations will not trigger alerts."
            ),
            recommendation=RULE.recommendation,
            passed=False,
        ))
    return findings
