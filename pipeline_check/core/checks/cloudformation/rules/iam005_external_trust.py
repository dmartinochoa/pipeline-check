"""IAM-005 (CloudFormation). CI/CD role trust missing sts:ExternalId."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext, as_str
from ..iam import _iam005_external_trust
from ._iam_context import cicd_role_view

RULE = Rule(
    id="IAM-005",
    title="CI/CD role trust policy missing sts:ExternalId",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-441",),
    recommendation=(
        "Add a ``Condition`` block with "
        "``StringEquals.sts:ExternalId`` to every trust-policy "
        "statement that allows an external AWS account to assume "
        "the role. Generate a high-entropy ExternalId once and "
        "store it in the relying party's configuration."
    ),
    docs_note=(
        "Parses ``AssumeRolePolicyDocument``. Walks every ``Allow`` "
        "statement whose ``Principal.AWS`` is an external account, "
        "and fires when no ``Condition`` carries ``sts:ExternalId``. "
        "Without it, the role is vulnerable to the confused-deputy "
        "pattern."
    ),
    exploit_example=(
        "# Vulnerable: cross-account trust policy with no\n"
        "# ``sts:ExternalId`` Condition. Confused-deputy class:\n"
        "# the third-party SaaS the role trusts can be tricked\n"
        "# into using it for the wrong customer.\n"
        "Resources:\n"
        "  Role:\n"
        "    Type: AWS::IAM::Role\n"
        "    Properties:\n"
        "      AssumeRolePolicyDocument:\n"
        "        Statement:\n"
        "          - Effect: Allow\n"
        "            Principal: { Service: codebuild.amazonaws.com }\n"
        "            Action: sts:AssumeRole\n"
        "          - Effect: Allow\n"
        "            Principal: { AWS: 'arn:aws:iam::999999999999:root' }\n"
        "            Action: sts:AssumeRole\n"
        "\n"
        "# Safe: require ``sts:ExternalId`` matching a value the\n"
        "# third-party SaaS shares only with your tenant.\n"
        "Resources:\n"
        "  Role:\n"
        "    Type: AWS::IAM::Role\n"
        "    Properties:\n"
        "      AssumeRolePolicyDocument:\n"
        "        Statement:\n"
        "          - Effect: Allow\n"
        "            Principal: { Service: codebuild.amazonaws.com }\n"
        "            Action: sts:AssumeRole\n"
        "          - Effect: Allow\n"
        "            Principal: { AWS: 'arn:aws:iam::999999999999:root' }\n"
        "            Action: sts:AssumeRole\n"
        "            Condition:\n"
        "              StringEquals:\n"
        "                sts:ExternalId: e7c1a0b3-abc-tenant-id"
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [
        _iam005_external_trust(
            role.properties,
            as_str(role.properties.get("RoleName")) or role.logical_id,
        )
        for role, _, _ in cicd_role_view(ctx)
    ]
