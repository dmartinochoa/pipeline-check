"""LMB-004 (CloudFormation). Lambda permission grants Principal '*'."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext
from ..services import _lambda

RULE = Rule(
    id="LMB-004",
    title="Lambda resource policy grants wildcard principal",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-8",),
    cwe=("CWE-732",),
    recommendation=(
        "Drop any ``AWS::Lambda::Permission`` with ``Principal: "
        "\"*\"``. Name the specific service principal or account "
        "that needs invoke, and scope further with ``SourceAccount`` "
        "/ ``SourceArn`` conditions."
    ),
    docs_note=(
        "Inspects every ``AWS::Lambda::Permission`` resource. Fires "
        "when ``Principal`` is ``\"*\"`` or any other wildcard form. "
        "A wildcard invoker exposes the function — and the role it "
        "executes with — to the whole internet."
    ),
    exploit_example=(
        "# Vulnerable: a Lambda permission grants ``Principal:\n"
        "# '*'``. Any AWS account on the internet can invoke\n"
        "# the function.\n"
        "Resources:\n"
        "  PublicPerm:\n"
        "    Type: AWS::Lambda::Permission\n"
        "    Properties:\n"
        "      FunctionName: !Ref Fn\n"
        "      Action: lambda:InvokeFunction\n"
        "      Principal: '*'\n"
        "\n"
        "# Safe: keep the wildcard ONLY when paired with a\n"
        "# service principal AND a SourceArn / SourceAccount\n"
        "# condition that proves the call originated from the\n"
        "# expected upstream.\n"
        "Resources:\n"
        "  ApiGwPerm:\n"
        "    Type: AWS::Lambda::Permission\n"
        "    Properties:\n"
        "      FunctionName: !Ref Fn\n"
        "      Action: lambda:InvokeFunction\n"
        "      Principal: apigateway.amazonaws.com\n"
        "      SourceArn: !Sub 'arn:aws:execute-api:${AWS::Region}:${AWS::AccountId}:abc123/*'"
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [f for f in _lambda(ctx) if f.check_id == "LMB-004"]
