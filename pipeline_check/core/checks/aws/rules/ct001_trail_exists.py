"""CT-001 — No active CloudTrail trail exists in the region."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="CT-001",
    title="No active CloudTrail trail in region",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-10",),
    cwe=("CWE-778",),
    recommendation=(
        "Create a CloudTrail trail that logs management events in this region "
        "and start logging. Without a trail, CodeBuild/CodePipeline/IAM API "
        "activity — including credential changes during a compromise — has "
        "no durable audit record."
    ),
    docs_note=(
        "CloudTrail is the only AWS-native source of record for management-"
        "plane API calls. A region with no active trail blinds incident "
        "responders: a pipeline compromise is invisible once the in-memory "
        "CloudWatch buffer rolls over."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    trails = catalog.cloudtrail_trails()
    # Any actively-logging trail covers this region: a multi-region trail
    # captures it unconditionally, a single-region trail is only returned
    # by DescribeTrails when its home region matches the one we're scanning.
    active = [t for t in trails if t.get("_IsLogging")]
    passed = bool(active)
    resource = "cloudtrail (region)"
    if passed:
        names = ", ".join(sorted({t.get("Name", "?") for t in active}))
        desc = f"Active CloudTrail trail(s) present: {names}."
    else:
        desc = (
            "No CloudTrail trail is actively logging in this region. API "
            "activity — including IAM and pipeline changes during an "
            "incident — has no durable audit record."
        )
    return [Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=resource, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )]
