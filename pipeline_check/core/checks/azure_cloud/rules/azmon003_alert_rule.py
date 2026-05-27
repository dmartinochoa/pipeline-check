"""AZMON-003. No alert rule for critical administrative operations."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="AZMON-003",
    title="No alert rule for critical administrative operations",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-10",),
    cwe=("CWE-778",),
    recommendation=(
        "Create activity log alert rules for high-impact operations: "
        "policy assignment changes, role assignment changes, security "
        "group modifications, and Key Vault access policy changes."
    ),
    docs_note=(
        "Activity log alerts provide near-real-time notification of "
        "control-plane changes. Without them, infrastructure "
        "modifications (new role assignments, NSG changes) go "
        "unnoticed until the next manual audit."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    alerts = catalog.activity_log_alerts()
    resource = f"subscription/{catalog.session.subscription_id}"
    has_alerts = len(alerts) > 0
    if has_alerts:
        findings.append(Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=resource,
            description=(
                f"Subscription has {len(alerts)} activity log alert "
                "rule(s) configured."
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
                "No activity log alert rules found. Critical "
                "administrative operations (role changes, policy "
                "changes, NSG modifications) are not monitored."
            ),
            recommendation=RULE.recommendation,
            passed=False,
        ))
    return findings
