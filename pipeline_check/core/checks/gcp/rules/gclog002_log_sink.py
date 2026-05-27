"""GCLOG-002. No log sink configured for audit logs."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="GCLOG-002",
    title="No log sink configured for audit logs",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-10",),
    cwe=("CWE-778",),
    recommendation=(
        "Create a log sink that exports audit logs to a durable "
        "destination (Cloud Storage, BigQuery, or Pub/Sub) for "
        "long-term retention and analysis."
    ),
    docs_note=(
        "Cloud Logging retains logs for a limited period (30 days "
        "by default for _Default bucket). A log sink exports logs "
        "to a destination with configurable retention, enabling "
        "forensic analysis months after an incident."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    sinks = catalog.log_sinks()
    active_sinks = [s for s in sinks if not s.get("disabled")]
    resource = f"projects/{catalog.session.project_id}"
    if active_sinks:
        findings.append(Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=resource,
            description=(
                f"Project has {len(active_sinks)} active log sink(s)."
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
                "No active log sinks found. Audit logs are not "
                "exported to a durable destination."
            ),
            recommendation=RULE.recommendation,
            passed=False,
        ))
    return findings
