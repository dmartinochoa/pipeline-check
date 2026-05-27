"""GCLOG-009. No log metric filter for route changes."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="GCLOG-009",
    title="No log metric filter for route changes",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-10",),
    cwe=("CWE-778",),
    recommendation=(
        "Create a log-based metric with a filter matching route "
        "changes (e.g. resource.type=\"gce_route\") and configure "
        "an alerting policy on it."
    ),
    docs_note=(
        "Route changes can redirect network traffic through "
        "attacker-controlled instances. A log-based metric and alert "
        "for route mutations catches unauthorized traffic redirection "
        "attempts in real time."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    metrics = catalog.log_metrics()
    resource = f"projects/{catalog.session.project_id}"
    found = any(
        "gce_route" in m.get("filter", "")
        for m in metrics
    )
    if found:
        findings.append(Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=resource,
            description=(
                "A log-based metric filter for route changes "
                "(gce_route) exists."
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
                "No log-based metric filter found for route changes. "
                "Route mutations will not trigger alerts."
            ),
            recommendation=RULE.recommendation,
            passed=False,
        ))
    return findings
