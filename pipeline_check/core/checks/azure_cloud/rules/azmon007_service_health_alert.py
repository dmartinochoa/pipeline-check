"""AZMON-007. No service health alert rule configured."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="AZMON-007",
    title="No service health alert rule configured",
    severity=Severity.LOW,
    owasp=("CICD-SEC-10",),
    cwe=("CWE-778",),
    recommendation=(
        "Create an activity log alert rule that monitors the "
        "'ServiceHealth' category. Configure notifications for "
        "service issues, planned maintenance, and health advisories "
        "affecting your subscription."
    ),
    docs_note=(
        "Service health alerts notify teams of Azure outages, "
        "degradations, and planned maintenance. Without them, "
        "pipeline failures caused by Azure platform issues are "
        "indistinguishable from application bugs until manually "
        "investigated."
    ),
)

_SERVICE_HEALTH_CATEGORY = "servicehealth"


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    alerts = catalog.activity_log_alerts()
    resource = f"subscription/{catalog.session.subscription_id}"

    has_service_health = False
    for alert in alerts:
        condition = getattr(alert, "condition", None)
        all_of = getattr(condition, "all_of", []) if condition else []
        for clause in all_of or []:
            field = str(getattr(clause, "field", "")).lower()
            equals = str(getattr(clause, "equals", "")).lower()
            if field == "category" and equals == _SERVICE_HEALTH_CATEGORY:
                has_service_health = True
                break
        if has_service_health:
            break

    if has_service_health:
        findings.append(Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=resource,
            description=(
                "A service health alert rule is configured for the "
                "subscription."
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
                "No service health alert rule is configured. Azure "
                "platform issues affecting CI/CD infrastructure will "
                "not generate proactive notifications."
            ),
            recommendation=RULE.recommendation,
            passed=False,
        ))
    return findings
