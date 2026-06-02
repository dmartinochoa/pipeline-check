"""IAM-006 (CloudFormation). Sensitive actions paired with Resource '*'."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext, as_str
from ..iam import _iam006_wildcard_resource
from ._iam_context import cicd_role_view

RULE = Rule(
    id="IAM-006",
    title="Sensitive actions granted with wildcard Resource",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-732",),
    recommendation=(
        "Scope ``Resource`` to specific ARNs (bucket ARNs, key "
        "ARNs, secret ARNs, role ARNs). Reserve ``Resource: \"*\"`` "
        "for actions that genuinely require it "
        "(``ec2:Describe*``, ``cloudwatch:DescribeAlarms``)."
    ),
    docs_note=(
        "Inspects every policy reachable from a CI/CD role. Fires "
        "on any ``Allow`` statement that pairs a sensitive service "
        "action (``s3:*``, ``kms:*``, ``secretsmanager:*``, "
        "``ssm:*``, ``iam:*``, ``sts:*``, ``dynamodb:*``, "
        "``lambda:*``, ``ec2:*``) with ``Resource: \"*\"``."
    ),
    exploit_example=(
        "# Vulnerable: a CI/CD role granting s3:* and\n"
        "# secretsmanager:* on Resource \"*\". A compromised build\n"
        "# step can read every secret and write every bucket.\n"
        "Resources:\n"
        "  CIRole:\n"
        "    Type: AWS::IAM::Role\n"
        "    Properties:\n"
        "      AssumeRolePolicyDocument:\n"
        "        Statement:\n"
        "          - Effect: Allow\n"
        "            Principal: { Service: codebuild.amazonaws.com }\n"
        "            Action: sts:AssumeRole\n"
        "      Policies:\n"
        "        - PolicyName: ci\n"
        "          PolicyDocument:\n"
        "            Statement:\n"
        "              - Effect: Allow\n"
        "                Action: [\"s3:*\", \"secretsmanager:GetSecretValue\"]\n"
        "                Resource: \"*\"\n"
        "\n"
        "# Safe: scope Resource to the specific ARNs the build needs.\n"
        "Resources:\n"
        "  CIRole:\n"
        "    Type: AWS::IAM::Role\n"
        "    Properties:\n"
        "      AssumeRolePolicyDocument:\n"
        "        Statement:\n"
        "          - Effect: Allow\n"
        "            Principal: { Service: codebuild.amazonaws.com }\n"
        "            Action: sts:AssumeRole\n"
        "      Policies:\n"
        "        - PolicyName: ci\n"
        "          PolicyDocument:\n"
        "            Statement:\n"
        "              - Effect: Allow\n"
        "                Action: [\"s3:GetObject\", \"s3:PutObject\"]\n"
        "                Resource: !Sub \"${ArtifactBucket.Arn}/*\""
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [
        _iam006_wildcard_resource(
            docs, as_str(role.properties.get("RoleName")) or role.logical_id,
        )
        for role, _, docs in cicd_role_view(ctx)
    ]
