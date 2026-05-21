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
    exploit_example=(
        "# Vulnerable: every stack-create writes a fresh access key\n"
        "# and stores the ``SecretAccessKey`` literal in the stack's\n"
        "# Outputs. Any IAM principal that can call\n"
        "# ``cloudformation:DescribeStacks`` on this stack reads the\n"
        "# secret. The key never rotates and only goes away when the\n"
        "# stack is torn down.\n"
        "Resources:\n"
        "  CiUser:\n"
        "    Type: AWS::IAM::User\n"
        "  CiAccessKey:\n"
        "    Type: AWS::IAM::AccessKey\n"
        "    Properties:\n"
        "      UserName: !Ref CiUser\n"
        "Outputs:\n"
        "  AccessKeyId:\n"
        "    Value: !Ref CiAccessKey\n"
        "  SecretAccessKey:\n"
        "    Value: !GetAtt CiAccessKey.SecretAccessKey\n"
        "\n"
        "# Safe: declare an IAM role with a short-lived assume-role\n"
        "# trust policy. For CI/CD, federate via GitHub OIDC\n"
        "# (``token.actions.githubusercontent.com``) so tokens expire\n"
        "# minutes after the workflow run. No long-lived secret ever\n"
        "# exists, and the trust policy enforces ``sub`` / ``aud``\n"
        "# claim equality on a single repo + ref.\n"
        "Resources:\n"
        "  CiRole:\n"
        "    Type: AWS::IAM::Role\n"
        "    Properties:\n"
        "      AssumeRolePolicyDocument:\n"
        "        Statement:\n"
        "          - Effect: Allow\n"
        "            Principal:\n"
        "              Federated: arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com\n"
        "            Action: sts:AssumeRoleWithWebIdentity\n"
        "            Condition:\n"
        "              StringEquals:\n"
        "                token.actions.githubusercontent.com:sub:\n"
        "                  repo:myorg/myrepo:ref:refs/heads/main"
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return _cf001_iam_access_key(ctx)
