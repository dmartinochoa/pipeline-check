"""LMB-001 (CloudFormation). Lambda has no CodeSigningConfigArn."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext
from ..services import _lambda

RULE = Rule(
    id="LMB-001",
    title="Lambda function has no code-signing config",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-345",),
    recommendation=(
        "Set ``CodeSigningConfigArn`` on every "
        "``AWS::Lambda::Function`` to an "
        "``AWS::Lambda::CodeSigningConfig`` whose allowed publishers "
        "list signing profiles your release pipeline uses."
    ),
    docs_note=(
        "Reads ``AWS::Lambda::Function.Properties.CodeSigningConfigArn``. "
        "Without it, Lambda accepts any zip the deployer can upload "
        "— there's no cryptographic check that the artifact came "
        "from the expected pipeline."
    ),
    exploit_example=(
        "# Vulnerable: a ``AWS::Lambda::Function`` with no\n"
        "# ``CodeSigningConfigArn``. Anyone with\n"
        "# ``lambda:UpdateFunctionCode`` ships arbitrary code\n"
        "# without signature verification.\n"
        "Resources:\n"
        "  Fn:\n"
        "    Type: AWS::Lambda::Function\n"
        "    Properties:\n"
        "      FunctionName: process-payment\n"
        "      Code: { S3Bucket: !Ref Deploys, S3Key: fn.zip }\n"
        "      Role: !GetAtt FnRole.Arn\n"
        "      Runtime: python3.12\n"
        "      Handler: index.handler\n"
        "      # no CodeSigningConfigArn\n"
        "\n"
        "# Safe: AWS Signer profile + CodeSigningConfig attached\n"
        "# to the function. Only signed code packages can be\n"
        "# deployed.\n"
        "Resources:\n"
        "  CSC:\n"
        "    Type: AWS::Lambda::CodeSigningConfig\n"
        "    Properties:\n"
        "      AllowedPublishers:\n"
        "        SigningProfileVersionArns: [!GetAtt Signer.ProfileVersionArn]\n"
        "      CodeSigningPolicies:\n"
        "        UntrustedArtifactOnDeployment: Enforce\n"
        "  Fn:\n"
        "    Type: AWS::Lambda::Function\n"
        "    Properties:\n"
        "      FunctionName: process-payment\n"
        "      CodeSigningConfigArn: !Ref CSC\n"
        "      # ...rest as above"
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [f for f in _lambda(ctx) if f.check_id == "LMB-001"]
