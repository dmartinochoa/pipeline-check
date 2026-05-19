"""CT-002 (CloudFormation). CloudTrail log-file validation disabled."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext
from ..extended import _cloudtrail

RULE = Rule(
    id="CT-002",
    title="CloudTrail log-file validation disabled",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-10",),
    cwe=("CWE-353",),
    recommendation=(
        "Set ``EnableLogFileValidation: true`` on every "
        "``AWS::CloudTrail::Trail``. CloudTrail then writes hash "
        "digests S3 cannot tamper with, post-incident validation "
        "can detect log forgery."
    ),
    docs_note=(
        "Reads ``AWS::CloudTrail::Trail.Properties.EnableLogFileValidation``. "
        "Without it, an attacker with ``s3:PutObject`` on the "
        "trail's bucket can rewrite event records and there's no "
        "cryptographic record of the original."
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [f for f in _cloudtrail(ctx) if f.check_id == "CT-002"]
