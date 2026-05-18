"""SSM-002 (Terraform). SecureString uses alias/aws/ssm, not a CMK."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..services import _ssm

RULE = Rule(
    id="SSM-002",
    title="SecureString uses alias/aws/ssm rather than a customer CMK",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-311",),
    recommendation=(
        "Set ``key_id`` on every ``SecureString`` ``aws_ssm_parameter`` "
        "to a customer-managed KMS CMK ARN. Default ``alias/aws/ssm`` "
        "is an AWS-owned key that can't be scoped or rotated by your "
        "key policy."
    ),
    docs_note=(
        "Reads ``aws_ssm_parameter.{type,key_id}``. Fires on a "
        "``SecureString`` whose ``key_id`` is empty or set to "
        "``alias/aws/ssm`` — the encryption boundary collapses back "
        "to ``ssm:GetParameter`` permissions alone."
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    return [f for f in _ssm(ctx) if f.check_id == "SSM-002"]
