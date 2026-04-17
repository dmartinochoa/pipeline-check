"""EB-002 — EventBridge rule has a wildcard target ARN."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="EB-002",
    title="EventBridge rule has a wildcard target ARN",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-8",),
    cwe=("CWE-441",),
    recommendation=(
        "Replace wildcard target ARNs with specific resource ARNs. "
        "EventBridge targets with ``*`` route events to any resource "
        "that matches the prefix — frequently triggering unintended "
        "Lambda invocations or SNS sends."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for rule_row in catalog.eventbridge_rules():
        name = rule_row.get("Name", "<unnamed>")
        for target in catalog.eventbridge_targets(name):
            arn = target.get("Arn", "") or ""
            if "*" in arn:
                findings.append(Finding(
                    check_id=RULE.id, title=RULE.title, severity=RULE.severity,
                    resource=f"{name}/{target.get('Id', '?')}",
                    description=f"Target ARN contains wildcard: {arn}.",
                    recommendation=RULE.recommendation, passed=False,
                ))
    return findings
