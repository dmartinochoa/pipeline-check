"""CT-001 (Terraform). No CloudTrail trail defined in the plan."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..extended import _cloudtrail_checks

RULE = Rule(
    id="CT-001",
    title="No active CloudTrail trail in region",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-10",),
    cwe=("CWE-778",),
    recommendation=(
        "Declare at least one ``aws_cloudtrail`` resource — typically "
        "a single ``is_multi_region_trail = true`` trail sending events "
        "to a write-protected S3 bucket. If trails are managed "
        "out-of-band (e.g. Control Tower), this rule's INFO baseline "
        "is the right place to suppress it."
    ),
    docs_note=(
        "Counts ``aws_cloudtrail`` resources in the plan. Without a "
        "trail (declared here or out-of-band), management-plane "
        "activity has no durable audit record — every incident reply "
        "starts from scratch."
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    return [f for f in _cloudtrail_checks(ctx) if f.check_id == "CT-001"]
