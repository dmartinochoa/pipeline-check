"""GCLOG-003. Log bucket retention less than 365 days."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="GCLOG-003",
    title="Log bucket retention less than 365 days",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-10",),
    cwe=("CWE-779",),
    recommendation=(
        "Set the log bucket retention period to at least 365 days. "
        "For the _Default bucket, update the retention via "
        "gcloud logging buckets update."
    ),
    docs_note=(
        "The default _Default log bucket retains logs for 30 days. "
        "Many compliance frameworks require at least one year of "
        "audit log retention."
    ),
)

_MIN_RETENTION_DAYS = 365


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for bucket in catalog.log_buckets():
        name = bucket.get("name", "<unnamed>")
        retention = bucket.get("retention_days", 30)
        passed = retention >= _MIN_RETENTION_DAYS
        if passed:
            desc = (
                f"Log bucket '{name}' retains logs for "
                f"{retention} days."
            )
        else:
            desc = (
                f"Log bucket '{name}' retains logs for only "
                f"{retention} days (minimum: {_MIN_RETENTION_DAYS})."
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
