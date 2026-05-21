"""IAM-004 (CloudFormation). CI/CD role policy grants iam:PassRole on '*'."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext, as_str
from ..iam import _iam004_passrole_wildcard
from ._iam_context import cicd_role_view

RULE = Rule(
    id="IAM-004",
    title="CI/CD role can PassRole to any role",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-269",),
    recommendation=(
        "Scope ``iam:PassRole`` to the specific role ARNs the "
        "pipeline must hand off to. Add an "
        "``iam:PassedToService`` condition so the role can only be "
        "passed to the service that actually consumes it."
    ),
    docs_note=(
        "Inspects every policy reachable from a CI/CD role. Fires "
        "on any ``Allow`` statement granting ``iam:PassRole`` (or "
        "``iam:*`` / ``*``) with ``Resource: \"*\"``. PassRole on a "
        "wildcard resource is the canonical AWS privilege-escalation "
        "primitive."
    ),
    exploit_example=(
        "# Vulnerable: ``iam:PassRole`` granted on\n"
        "# ``Resource: '*'``. The pipeline role can pass any\n"
        "# role to any AWS service. Combined with a service\n"
        "# that runs code (Lambda, CodeBuild, ECS), this is a\n"
        "# direct privilege-escalation primitive.\n"
        "Resources:\n"
        "  PipelineRole:\n"
        "    Type: AWS::IAM::Role\n"
        "    Properties:\n"
        "      Policies:\n"
        "        - PolicyName: pass-anything\n"
        "          PolicyDocument:\n"
        "            Statement:\n"
        "              - Effect: Allow\n"
        "                Action: iam:PassRole\n"
        "                Resource: '*'\n"
        "\n"
        "# Safe: scope ``Resource`` to specific roles the\n"
        "# pipeline actually needs to pass (CodeBuild's service\n"
        "# role, CodeDeploy's service role). New service\n"
        "# additions force a policy review.\n"
        "Resources:\n"
        "  PipelineRole:\n"
        "    Type: AWS::IAM::Role\n"
        "    Properties:\n"
        "      Policies:\n"
        "        - PolicyName: pass-specific\n"
        "          PolicyDocument:\n"
        "            Statement:\n"
        "              - Effect: Allow\n"
        "                Action: iam:PassRole\n"
        "                Resource:\n"
        "                  - !GetAtt CodeBuildServiceRole.Arn\n"
        "                  - !GetAtt CodeDeployServiceRole.Arn"
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [
        _iam004_passrole_wildcard(
            docs, as_str(role.properties.get("RoleName")) or role.logical_id,
        )
        for role, _, docs in cicd_role_view(ctx)
    ]
