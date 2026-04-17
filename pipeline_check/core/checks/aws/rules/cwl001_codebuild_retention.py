"""CWL-001 — CodeBuild log groups have no retention policy."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="CWL-001",
    title="CodeBuild log group has no retention policy",
    severity=Severity.LOW,
    owasp=("CICD-SEC-10",),
    cwe=("CWE-778",),
    recommendation=(
        "Set a retention policy on every ``/aws/codebuild/*`` log group. "
        "The default is 'Never Expire', which both racks up storage cost "
        "and keeps logs indefinitely past any compliance window."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for lg in catalog.log_groups("/aws/codebuild/"):
        name = lg.get("logGroupName", "<unnamed>")
        retention = lg.get("retentionInDays")
        passed = bool(retention)
        if passed:
            desc = f"Log group '{name}' has a {retention}-day retention policy."
        else:
            desc = (
                f"Log group '{name}' has no retention policy (logs kept "
                "forever). Set a retention in days appropriate for your "
                "compliance requirements."
            )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=name, description=desc,
            recommendation=RULE.recommendation, passed=passed,
        ))
    return findings
