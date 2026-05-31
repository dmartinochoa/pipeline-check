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
        "# Vulnerable: a CI/CD role granting s3:* on Resource \"*\".\n"
        "Resources:\n"
        "  CIRole:\n"
        "    Type: AWS::IAM::Role\n"
        "    Properties:\n"
        "      Policies:\n"
        "        - PolicyName: ci\n"
        "          PolicyDocument:\n"
        "            Statement:\n"
        "              - Effect: Allow\n"
        "                Action: [\"s3:*\", \"secretsmanager:GetSecretValue\"]\n"
        "                Resource: \"*\"\n"
        "\n"
        "# Attack: the build role can read and write every bucket and\n"
        "# every secret in the account, not just its own. A compromised\n"
        "# build step (an injected buildspec, a malicious dependency)\n"
        "# uses the role to pull production secrets and tamper with\n"
        "# unrelated data in one call.\n"
        "\n"
        "# Safe: scope Resource to the specific ARNs the build needs.\n"
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
