"""LMB-002 (CloudFormation). Lambda Function URL has AuthType = NONE."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext
from ..services import _lambda

RULE = Rule(
    id="LMB-002",
    title="Lambda Function URL configured with AuthType = NONE",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-8",),
    cwe=("CWE-862",),
    recommendation=(
        "Set ``AuthType: AWS_IAM`` on every "
        "``AWS::Lambda::Url`` and grant invoke via explicit "
        "``AWS::Lambda::Permission`` resources rather than leaving "
        "the URL public."
    ),
    docs_note=(
        "Reads ``AWS::Lambda::Url.Properties.AuthType``. The "
        "``NONE`` setting exposes the function over a public HTTPS "
        "endpoint with no authentication."
    ),
    exploit_example=(
        "# Vulnerable: a Function URL with ``AuthType: NONE`` is\n"
        "# on the public internet without auth.\n"
        "Resources:\n"
        "  Url:\n"
        "    Type: AWS::Lambda::Url\n"
        "    Properties:\n"
        "      TargetFunctionArn: !GetAtt Fn.Arn\n"
        "      AuthType: NONE\n"
        "\n"
        "# Safe: ``AWS_IAM`` requires IAM-signed requests.\n"
        "Resources:\n"
        "  Url:\n"
        "    Type: AWS::Lambda::Url\n"
        "    Properties:\n"
        "      TargetFunctionArn: !GetAtt Fn.Arn\n"
        "      AuthType: AWS_IAM"
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [f for f in _lambda(ctx) if f.check_id == "LMB-002"]
