"""CW-001. No CloudWatch alarm on CodeBuild FailedBuilds metric."""
from __future__ import annotations

from typing import Any

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
        "one, repeated build failures during a compromise, or a "
        "runaway fork-PR build, won't reach on-call."
    ),
    docs_note=(
        "Failure-rate signals are how on-call learns about an "
        "unfamiliar build crashing in a loop, an attacker probing the "
        "build environment, or a CI quota being exhausted. CloudWatch "
        "captures the ``FailedBuilds`` metric automatically, the "
        "alarm is the missing fan-out."
    ),
)


def _alarm_covers_failed_builds(alarm: dict[str, Any]) -> bool:
    """Return True when *alarm* monitors the AWS/CodeBuild FailedBuilds metric.

    A standard metric alarm carries top-level ``Namespace`` and ``MetricName``
    fields. A metric-math alarm instead carries a ``Metrics`` list where each
    entry may have a ``MetricStat.Metric`` sub-object. Check both shapes.
    """
    if (
        alarm.get("Namespace") == "AWS/CodeBuild"
        and alarm.get("MetricName") == "FailedBuilds"
    ):
        return True
    # Metric-math alarms: scan the Metrics list for a MetricStat entry.
    for entry in alarm.get("Metrics") or []:
        metric_stat = entry.get("MetricStat") or {}
        metric = metric_stat.get("Metric") or {}
        if (
            metric.get("Namespace") == "AWS/CodeBuild"
            and metric.get("MetricName") == "FailedBuilds"
        ):
            return True
    return False


def check(catalog: ResourceCatalog) -> list[Finding]:
    # No CodeBuild projects in this account/region — the alarm is irrelevant.
    # The CFN/Terraform mirrors apply the same suppression so behavior is
    # consistent across all scan modes.
    if not catalog.codebuild_projects():
        return []
    try:
        client = catalog.client("cloudwatch")
    except Exception:
        return []
    try:
        resp = client.describe_alarms(AlarmTypes=["MetricAlarm"])
    except ClientError:
        return []
    alarms = resp.get("MetricAlarms", [])
    covered = any(_alarm_covers_failed_builds(a) for a in alarms)
    return [Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="cloudwatch",
        description=(
            "CloudWatch alarm on AWS/CodeBuild FailedBuilds is configured."
            if covered else
            "No alarm found on AWS/CodeBuild FailedBuilds, failures go unnoticed."
        ),
        recommendation=RULE.recommendation, passed=covered,
    )]
