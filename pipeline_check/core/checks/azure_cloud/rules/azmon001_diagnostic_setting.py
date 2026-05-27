"""AZMON-001. Subscription has no diagnostic setting for Activity Log."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="AZMON-001",
    title="No diagnostic setting for subscription Activity Log",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-10",),
    cwe=("CWE-778",),
    recommendation=(
        "Create a diagnostic setting on the subscription that sends "
        "Activity Log events to a Log Analytics workspace, Storage "
        "account, or Event Hub. Enable the Administrative, Security, "
        "and Policy categories at minimum."
    ),
    docs_note=(
        "The Activity Log records control-plane operations (role "
        "assignments, resource creation, policy changes). Without a "
        "diagnostic setting, these events are retained for only 90 "
        "days and are not queryable in Log Analytics."
    ),
    exploit_example=(
        "An attacker modifies an NSG to allow inbound SSH. Without "
        "a diagnostic setting forwarding Activity Log events, the "
        "change is invisible to the SOC after 90 days."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    settings = catalog.diagnostic_settings()
    has_setting = len(settings) > 0
    resource = f"subscription/{catalog.session.subscription_id}"
    if has_setting:
        findings.append(Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=resource,
            description=(
                f"Subscription has {len(settings)} diagnostic "
                "setting(s) configured for the Activity Log."
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
                "No diagnostic settings found for the subscription "
                "Activity Log. Control-plane events are retained for "
                "only 90 days and are not forwarded to a durable sink."
            ),
            recommendation=RULE.recommendation,
            passed=False,
        ))
    return findings
