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
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [f for f in _cloudtrail(ctx) if f.check_id == "CT-001"]
