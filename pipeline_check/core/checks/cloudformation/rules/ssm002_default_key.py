"""SSM-002 (CloudFormation). SecureString uses default key, not a CMK."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext
from ..services import _ssm

RULE = Rule(
    id="SSM-002",
    title="SecureString uses alias/aws/ssm rather than a customer CMK",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-311",),
    recommendation=(
        "Set ``KeyId`` on every ``SecureString`` "
        "``AWS::SSM::Parameter`` to a customer-managed KMS CMK ARN. "
        "Default ``alias/aws/ssm`` is an AWS-owned key that can't "
        "be scoped or rotated by your key policy."
    ),
    docs_note=(
        "Reads ``AWS::SSM::Parameter.Properties.{Type,KeyId}``. "
        "Fires on a ``SecureString`` whose ``KeyId`` is empty or "
        "set to ``alias/aws/ssm``."
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [f for f in _ssm(ctx) if f.check_id == "SSM-002"]
