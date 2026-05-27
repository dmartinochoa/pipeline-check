"""GCLOG-010. No log metric filter for Cloud SQL config changes."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="GCLOG-010",
    title="No log metric filter for Cloud SQL config changes",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-10",),
    cwe=("CWE-778",),
    recommendation=(
        "Create a log-based metric with a filter matching Cloud SQL "
        "configuration changes (e.g. "
        "protoPayload.methodName=\"cloudsql.instances.update\") and "
        "configure an alerting policy on it."
    ),
    docs_note=(
        "Cloud SQL configuration changes (disabling SSL, enabling "
        "public IP, modifying database flags) can weaken security. "
        "A log-based metric and alert for these mutations catches "
        "unauthorized database configuration changes."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    metrics = catalog.log_metrics()
    resource = f"projects/{catalog.session.project_id}"
    found = any(
        "cloudsql.instances.update" in m.get("filter", "")
        for m in metrics
    )
    if found:
        findings.append(Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=resource,
            description=(
                "A log-based metric filter for Cloud SQL config "
                "changes (cloudsql.instances.update) exists."
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
                "No log-based metric filter found for Cloud SQL "
                "config changes. Instance updates will not trigger "
                "alerts."
            ),
            recommendation=RULE.recommendation,
            passed=False,
        ))
    return findings
