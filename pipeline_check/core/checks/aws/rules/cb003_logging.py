"""CB-003 — CodeBuild project has no CloudWatch or S3 logging."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="CB-003",
    title="Build logging not enabled",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-10",),
    cwe=("CWE-778",),
    recommendation=(
        "Enable CloudWatch Logs or S3 logging in the CodeBuild project "
        "configuration to maintain a durable audit trail of all build "
        "activity."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for project in catalog.codebuild_projects():
        name = project.get("name", "<unnamed>")
        logs = project.get("logsConfig", {})
        cw_enabled = logs.get("cloudWatchLogs", {}).get("status") == "ENABLED"
        s3_enabled = logs.get("s3Logs", {}).get("status") == "ENABLED"
        passed = cw_enabled or s3_enabled
        if passed:
            dest = []
            if cw_enabled:
                dest.append("CloudWatch Logs")
            if s3_enabled:
                dest.append("S3")
            desc = f"Build logging is enabled ({' and '.join(dest)})."
        else:
            desc = (
                "Neither CloudWatch Logs nor S3 logging is enabled for this "
                "project. Without logs, build activity cannot be audited and "
                "security incidents cannot be investigated or attributed."
            )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=name, description=desc,
            recommendation=RULE.recommendation, passed=passed,
        ))
    return findings
