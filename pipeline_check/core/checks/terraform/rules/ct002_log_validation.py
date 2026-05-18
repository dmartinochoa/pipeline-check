"""CT-002 (Terraform). CloudTrail log-file validation disabled."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..extended import _cloudtrail_checks

RULE = Rule(
    id="CT-002",
    title="CloudTrail log-file validation disabled",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-10",),
    cwe=("CWE-353",),
    recommendation=(
        "Set ``enable_log_file_validation = true`` on every "
        "``aws_cloudtrail`` resource. CloudTrail will then write "
        "hash digests S3 cannot tamper with, post-incident validation "
        "can detect log forgery."
    ),
    docs_note=(
        "Reads ``aws_cloudtrail.enable_log_file_validation``. "
        "Without it, an attacker with ``s3:PutObject`` on the trail's "
        "bucket can rewrite event records and there's no "
        "cryptographic record of the original."
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    return [f for f in _cloudtrail_checks(ctx) if f.check_id == "CT-002"]
