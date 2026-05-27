"""GCLOG-007. No log metric filter for IAM policy changes."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="GCLOG-007",
    title="No log metric filter for IAM policy changes",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-10",),
    cwe=("CWE-778",),
    recommendation=(
        "Create a log-based metric with a filter matching IAM policy "
        "changes (e.g. resource.type=\"project\" AND "
        "protoPayload.methodName=\"SetIamPolicy\") and configure an "
        "alerting policy on it."
    ),
    docs_note=(
        "IAM policy changes are high-impact actions. A log-based "
        "metric and alert ensures that unexpected privilege escalation "
        "or access grants trigger an immediate notification rather "
        "than going unnoticed in the audit log."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    metrics = catalog.log_metrics()
    resource = f"projects/{catalog.session.project_id}"
    found = any(
        "SetIamPolicy" in m.get("filter", "")
        for m in metrics
    )
    if found:
        findings.append(Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=resource,
            description=(
                "A log-based metric filter for IAM policy changes "
                "(SetIamPolicy) exists."
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
                "No log-based metric filter found for IAM policy "
                "changes. SetIamPolicy calls will not trigger alerts."
            ),
            recommendation=RULE.recommendation,
            passed=False,
        ))
    return findings
