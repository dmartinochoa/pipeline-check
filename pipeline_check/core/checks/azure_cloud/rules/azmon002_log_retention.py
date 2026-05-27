"""AZMON-002. Activity Log retention less than 365 days."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="AZMON-002",
    title="Activity Log retention less than 365 days",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-10",),
    cwe=("CWE-779",),
    recommendation=(
        "Configure the diagnostic setting's destination (Log "
        "Analytics workspace or Storage account) with a retention "
        "period of at least 365 days."
    ),
    docs_note=(
        "Many compliance frameworks (PCI DSS, SOC 2) require at "
        "least one year of audit log retention. A short retention "
        "period limits forensic capability after a security incident."
    ),
)

_MIN_RETENTION_DAYS = 365


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    settings = catalog.diagnostic_settings()
    if not settings:
        return findings
    resource = f"subscription/{catalog.session.subscription_id}"
    for setting in settings:
        name = getattr(setting, "name", "<unnamed>")
        logs = getattr(setting, "logs", []) or []
        min_retention = None
        for log_entry in logs:
            rp = getattr(log_entry, "retention_policy", None)
            if rp and getattr(rp, "enabled", False):
                days = getattr(rp, "days", 0) or 0
                if min_retention is None or days < min_retention:
                    min_retention = days
        if min_retention is None:
            passed = True
            desc = (
                f"Diagnostic setting '{name}' does not set an explicit "
                "retention policy (retention is managed at the "
                "destination)."
            )
        elif min_retention >= _MIN_RETENTION_DAYS:
            passed = True
            desc = (
                f"Diagnostic setting '{name}' retains logs for "
                f"{min_retention} days (>= {_MIN_RETENTION_DAYS})."
            )
        else:
            passed = False
            desc = (
                f"Diagnostic setting '{name}' retains logs for only "
                f"{min_retention} days (minimum: {_MIN_RETENTION_DAYS})."
            )
        findings.append(Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=f"{resource}/{name}",
            description=desc,
            recommendation=RULE.recommendation,
            passed=passed,
        ))
    return findings
