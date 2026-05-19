"""CF-001 (CloudFormation-only). Static AWS::IAM::AccessKey in template."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext
from ..phase4 import _cf001_iam_access_key

RULE = Rule(
    id="CF-001",
    title="Template declares AWS::IAM::AccessKey (long-lived credential)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6",),
    cwe=("CWE-798",),
    recommendation=(
        "Replace static keys with role-based access: an "
        "``AWS::IAM::Role`` plus an "
        "``AWS::IAM::OIDCProvider`` for CI, or an IAM role for "
        "service-to-service auth. Static keys live forever in stack "
        "outputs and any tool that ever read them."
    ),
    docs_note=(
        "Fires on every ``AWS::IAM::AccessKey`` in the template. "
        "CloudFormation writes the resulting ``SecretAccessKey`` to "
        "stack outputs — the secret is now in every stack update "
        "log and every ``DescribeStacks`` response."
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return _cf001_iam_access_key(ctx)
