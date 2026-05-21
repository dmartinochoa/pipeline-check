"""CT-001 (CloudFormation). No CloudTrail trail defined in the template."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext
from ..extended import _cloudtrail

RULE = Rule(
    id="CT-001",
    title="No active CloudTrail trail in region",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-10",),
    cwe=("CWE-778",),
    recommendation=(
        "Declare at least one ``AWS::CloudTrail::Trail`` — typically "
        "a single ``IsMultiRegionTrail: true`` trail sending events "
        "to a write-protected S3 bucket. If trails are managed "
        "out-of-band, baseline this rule's INFO emission."
    ),
    docs_note=(
        "Counts ``AWS::CloudTrail::Trail`` resources. Without a "
        "trail (declared here or out-of-band), management-plane "
        "activity has no durable audit record."
    ),
    exploit_example=(
        "# Vulnerable: no ``AWS::CloudTrail::Trail`` resource in\n"
        "# the template covering this region. API calls aren't\n"
        "# audited; incident response can't reconstruct an\n"
        "# attacker's actions.\n"
        "Resources:\n"
        "  # ... no CloudTrail::Trail anywhere\n"
        "\n"
        "# Safe: a multi-region trail logging to a versioned S3\n"
        "# bucket with log-file validation enabled. Pair with\n"
        "# CloudWatch alarms on common compromise signals.\n"
        "Resources:\n"
        "  Trail:\n"
        "    Type: AWS::CloudTrail::Trail\n"
        "    Properties:\n"
        "      TrailName: org-wide-trail\n"
        "      S3BucketName: !Ref CloudTrailLogsBucket\n"
        "      IsMultiRegionTrail: true\n"
        "      IncludeGlobalServiceEvents: true\n"
        "      EnableLogFileValidation: true\n"
        "      IsLogging: true"
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [f for f in _cloudtrail(ctx) if f.check_id == "CT-001"]
