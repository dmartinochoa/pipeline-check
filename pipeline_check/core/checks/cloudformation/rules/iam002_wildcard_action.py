"""IAM-002 (CloudFormation). CI/CD role policy has Action: '*'."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext, as_str
from ..iam import _iam002_wildcard_action
from ._iam_context import cicd_role_view

RULE = Rule(
    id="IAM-002",
    title="CI/CD role has wildcard Action in attached policy",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-269",),
    recommendation=(
        "Enumerate the specific IAM actions the role needs and drop "
        "``Action: \"*\"`` entirely. Access Analyzer or "
        "CloudTrail-based policy generation can suggest a minimum set."
    ),
    docs_note=(
        "Walks every policy document attached to a CI/CD role: "
        "inline ``Role.Policies`` plus the resolved "
        "``AWS::IAM::ManagedPolicy`` referenced via "
        "``ManagedPolicyArns: { Ref: … }``. Fires when any "
        "``Allow`` statement names ``\"*\"`` in ``Action``."
    ),
    exploit_example=(
        "# Vulnerable: a CI/CD role with ``Action: '*'`` (or a\n"
        "# service-prefix wildcard like ``s3:*``). Any compromise\n"
        "# of a pipeline using this role becomes admin on the\n"
        "# resource scope.\n"
        "Resources:\n"
        "  BuildRole:\n"
        "    Type: AWS::IAM::Role\n"
        "    Properties:\n"
        "      AssumeRolePolicyDocument: {...}\n"
        "      Policies:\n"
        "        - PolicyName: build\n"
        "          PolicyDocument:\n"
        "            Statement:\n"
        "              - Effect: Allow\n"
        "                Action: 's3:*'\n"
        "                Resource: '*'\n"
        "\n"
        "# Safe: enumerate the actions the pipeline actually\n"
        "# needs and scope ``Resource`` to specific bucket ARNs.\n"
        "Resources:\n"
        "  BuildRole:\n"
        "    Type: AWS::IAM::Role\n"
        "    Properties:\n"
        "      AssumeRolePolicyDocument: {...}\n"
        "      Policies:\n"
        "        - PolicyName: build\n"
        "          PolicyDocument:\n"
        "            Statement:\n"
        "              - Effect: Allow\n"
        "                Action:\n"
        "                  - s3:GetObject\n"
        "                  - s3:PutObject\n"
        "                  - s3:ListBucket\n"
        "                Resource:\n"
        "                  - !GetAtt ArtifactsBucket.Arn\n"
        "                  - !Sub '${ArtifactsBucket.Arn}/*'"
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [
        _iam002_wildcard_action(
            docs, as_str(role.properties.get("RoleName")) or role.logical_id,
        )
        for role, _, docs in cicd_role_view(ctx)
    ]
