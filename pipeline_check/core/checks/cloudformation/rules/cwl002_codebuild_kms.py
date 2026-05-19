"""CWL-002 (CloudFormation). CodeBuild log group not KMS-encrypted."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext
from ..extended import _cw_logs

RULE = Rule(
    id="CWL-002",
    title="CodeBuild log group not KMS-encrypted",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-311",),
    recommendation=(
        "Set ``KmsKeyId`` on every ``AWS::Logs::LogGroup`` whose "
        "name starts with ``/aws/codebuild/`` to a customer-managed "
        "CMK ARN. Build logs commonly carry secret fragments and "
        "environment dumps."
    ),
    docs_note=(
        "Reads ``AWS::Logs::LogGroup.Properties.KmsKeyId`` on log "
        "groups whose name starts with ``/aws/codebuild/``. Without a "
        "CMK, logs are encrypted with an AWS-owned key, which can't "
        "be audited or scoped by IAM."
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [f for f in _cw_logs(ctx) if f.check_id == "CWL-002"]
