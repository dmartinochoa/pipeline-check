"""CW-001 — No CloudWatch alarm on CodeBuild FailedBuilds metric."""
from __future__ import annotations

from botocore.exceptions import ClientError

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="CW-001",
    title="No CloudWatch alarm on CodeBuild FailedBuilds metric",
    severity=Severity.LOW,
    owasp=("CICD-SEC-10",),
    cwe=("CWE-778",),
    recommendation=(
        "Create a CloudWatch alarm on the ``AWS/CodeBuild`` namespace "
        "``FailedBuilds`` metric (aggregated or per-project). Without "
        "one, repeated build failures during a compromise — or a "
        "runaway fork-PR build — won't reach on-call."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    try:
        client = catalog.client("cloudwatch")
    except Exception:  # noqa: BLE001
        return []
    try:
        resp = client.describe_alarms(AlarmTypes=["MetricAlarm"])
    except ClientError:
        return []
    alarms = resp.get("MetricAlarms", [])
    covered = any(
        a.get("Namespace") == "AWS/CodeBuild" and a.get("MetricName") == "FailedBuilds"
        for a in alarms
    )
    return [Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="cloudwatch",
        description=(
            "CloudWatch alarm on AWS/CodeBuild FailedBuilds is configured."
            if covered else
            "No alarm found on AWS/CodeBuild FailedBuilds — failures go unnoticed."
        ),
        recommendation=RULE.recommendation, passed=covered,
    )]
