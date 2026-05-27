"""AZMON-006. Log Analytics workspace retention less than 365 days."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="AZMON-006",
    title="Log Analytics workspace retention less than 365 days",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-10",),
    cwe=("CWE-779",),
    recommendation=(
        "Set the Log Analytics workspace retention to at least 365 "
        "days. Many compliance frameworks (PCI DSS, SOC 2) require "
        "one year of log retention for forensic readiness."
    ),
    docs_note=(
        "The default Log Analytics retention is 30 days. Audit logs "
        "and security events retained for less than 365 days may be "
        "unavailable during post-incident investigations."
    ),
)

_MIN_RETENTION_DAYS = 365


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for workspace in catalog.log_analytics_workspaces():
        name = getattr(workspace, "name", "<unnamed>")
        retention = getattr(workspace, "retention_in_days", 30)
        if retention is None:
            retention = 30
        passed = retention >= _MIN_RETENTION_DAYS
        if passed:
            desc = (
                f"Log Analytics workspace '{name}' retains data for "
                f"{retention} days (>= {_MIN_RETENTION_DAYS})."
            )
        else:
            desc = (
                f"Log Analytics workspace '{name}' retains data for "
                f"only {retention} days (minimum: "
                f"{_MIN_RETENTION_DAYS})."
            )
        findings.append(Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=name,
            description=desc,
            recommendation=RULE.recommendation,
            passed=passed,
        ))
    return findings
