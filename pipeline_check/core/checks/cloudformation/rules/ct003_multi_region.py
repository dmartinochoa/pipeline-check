"""CT-003 (CloudFormation). CloudTrail trail is single-region."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext
from ..extended import _cloudtrail

RULE = Rule(
    id="CT-003",
    title="CloudTrail trail is not multi-region",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-10",),
    cwe=("CWE-778",),
    recommendation=(
        "Set ``IsMultiRegionTrail: true`` so a single trail captures "
        "activity from every region. A region-scoped trail misses "
        "anything an attacker does in another region."
    ),
    docs_note=(
        "Reads ``AWS::CloudTrail::Trail.Properties.IsMultiRegionTrail``. "
        "Multi-region is the only configuration that guarantees "
        "you'll see ``CreateAccessKey`` in ``ap-south-1`` from your "
        "``us-east-1`` trail."
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [f for f in _cloudtrail(ctx) if f.check_id == "CT-003"]
