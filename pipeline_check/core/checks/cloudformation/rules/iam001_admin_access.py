"""IAM-001 (CloudFormation). CI/CD role has AdministratorAccess."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext, as_str
from ..iam import _iam001_admin_access
from ._iam_context import cicd_role_view

RULE = Rule(
    id="IAM-001",
    title="CI/CD role has AdministratorAccess policy attached",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-269",),
    recommendation=(
        "Replace ``AdministratorAccess`` with least-privilege "
        "policies that grant only the specific actions and "
        "resources the build needs. Pair with IAM-003 (permissions "
        "boundary) so a future policy edit can't quietly "
        "re-broaden the role."
    ),
    docs_note=(
        "Considers a role CI/CD-scoped when its "
        "``AssumeRolePolicyDocument`` trusts "
        "``codebuild.amazonaws.com``, "
        "``codepipeline.amazonaws.com``, or "
        "``codedeploy.amazonaws.com``. Reads ``ManagedPolicyArns`` "
        "literal entries; fires when "
        "``arn:aws:iam::aws:policy/AdministratorAccess`` appears."
    ),
    exploit_example=(
        "# Vulnerable: any compromise of the CodeBuild project (a\n"
        "# poisoned buildspec, a malicious dependency in the build's\n"
        "# package set, a leaked GitHub token that can update the\n"
        "# buildspec) becomes ``aws *`` against the account. Every\n"
        "# secret in Secrets Manager, every S3 object, every IAM\n"
        "# entity is in scope. AdministratorAccess covers actions\n"
        "# AWS hasn't even shipped yet — the policy grows silently.\n"
        "Resources:\n"
        "  BuildRole:\n"
        "    Type: AWS::IAM::Role\n"
        "    Properties:\n"
        "      AssumeRolePolicyDocument:\n"
        "        Statement:\n"
        "          - Effect: Allow\n"
        "            Principal: { Service: codebuild.amazonaws.com }\n"
        "            Action: sts:AssumeRole\n"
        "      ManagedPolicyArns:\n"
        "        - arn:aws:iam::aws:policy/AdministratorAccess\n"
        "\n"
        "# Safe: enumerate the verbs and resource ARNs the build\n"
        "# actually needs. Pair with a ``PermissionsBoundary`` so a\n"
        "# future policy edit (drift, a stack update, a teammate's\n"
        "# patch) cannot quietly re-broaden the role. New service\n"
        "# requirements force a policy review.\n"
        "Resources:\n"
        "  BuildRole:\n"
        "    Type: AWS::IAM::Role\n"
        "    Properties:\n"
        "      AssumeRolePolicyDocument:\n"
        "        Statement:\n"
        "          - Effect: Allow\n"
        "            Principal: { Service: codebuild.amazonaws.com }\n"
        "            Action: sts:AssumeRole\n"
        "      PermissionsBoundary: !Ref CiPermissionsBoundary\n"
        "      Policies:\n"
        "        - PolicyName: build-narrow\n"
        "          PolicyDocument:\n"
        "            Statement:\n"
        "              - Effect: Allow\n"
        "                Action:\n"
        "                  - s3:GetObject\n"
        "                  - s3:PutObject\n"
        "                Resource:\n"
        "                  - arn:aws:s3:::my-build-artifacts/*"
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [
        _iam001_admin_access(
            arns, as_str(role.properties.get("RoleName")) or role.logical_id,
        )
        for role, arns, _ in cicd_role_view(ctx)
    ]
