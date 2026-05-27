"""GCLOG-011. No log metric filter for custom role changes."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="GCLOG-011",
    title="No log metric filter for custom role changes",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-10",),
    cwe=("CWE-778",),
    recommendation=(
        "Create a log-based metric with a filter matching custom "
        "role changes (e.g. resource.type=\"iam_role\") and configure "
        "an alerting policy on it."
    ),
    docs_note=(
        "Custom role changes can grant new permissions or weaken "
        "existing access controls. A log-based metric and alert for "
        "custom role mutations catches privilege escalation via role "
        "modification."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    metrics = catalog.log_metrics()
    resource = f"projects/{catalog.session.project_id}"
    found = any(
        "iam_role" in m.get("filter", "")
        for m in metrics
    )
    if found:
        findings.append(Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=resource,
            description=(
                "A log-based metric filter for custom role changes "
                "(iam_role) exists."
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
                "No log-based metric filter found for custom role "
                "changes. Role mutations will not trigger alerts."
            ),
            recommendation=RULE.recommendation,
            passed=False,
        ))
    return findings
