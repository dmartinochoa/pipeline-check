"""CB-001 (CloudFormation). Plaintext-secret CodeBuild environment variables."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext
from ..codebuild import _cb001_plaintext_secrets

RULE = Rule(
    id="CB-001",
    title="Secrets in plaintext environment variables",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-6",),
    cwe=("CWE-798",),
    recommendation=(
        "Move secrets to AWS Secrets Manager or SSM Parameter Store and "
        "reference them via ``Type: SECRETS_MANAGER`` or "
        "``Type: PARAMETER_STORE`` on the corresponding "
        "``Environment.EnvironmentVariables`` entry."
    ),
    docs_note=(
        "Walks every ``AWS::CodeBuild::Project``'s "
        "``Properties.Environment.EnvironmentVariables`` list. Flags "
        "any entry whose ``Type`` is ``PLAINTEXT`` (or absent — the "
        "CFN default) when (a) the ``Name`` matches a secret-like "
        "pattern (``PASSWORD``, ``TOKEN``, ``API_KEY``, …) or (b) the "
        "``Value`` matches a known credential shape (AKIA/ASIA, "
        "GitHub tokens, JWTs)."
    ),
    exploit_example=(
        "# Vulnerable: every build run prints the env to CloudWatch\n"
        "# Logs (and any ``echo $NPM_TOKEN`` in the buildspec lands\n"
        "# in plaintext too). The template itself sits in version\n"
        "# control, so the token leaks to anyone with read access\n"
        "# to the repo. Stack drift detection surfaces no warning\n"
        "# because the value is the template's truth.\n"
        "Resources:\n"
        "  BuildProject:\n"
        "    Type: AWS::CodeBuild::Project\n"
        "    Properties:\n"
        "      Name: my-build\n"
        "      Environment:\n"
        "        Type: LINUX_CONTAINER\n"
        "        ComputeType: BUILD_GENERAL1_SMALL\n"
        "        Image: aws/codebuild/standard:7.0\n"
        "        EnvironmentVariables:\n"
        "          - Name: NPM_TOKEN\n"
        "            Type: PLAINTEXT\n"
        "            Value: npm_xyz123abc456...\n"
        "\n"
        "# Safe: keep the secret in Secrets Manager (or SSM\n"
        "# Parameter Store with a ``SecureString`` type) and\n"
        "# reference it by ARN. CodeBuild's runtime injects the\n"
        "# decrypted value just-in-time, so the template carries\n"
        "# only the resource reference and the log line shows\n"
        "# the env name without its value.\n"
        "Resources:\n"
        "  BuildProject:\n"
        "    Type: AWS::CodeBuild::Project\n"
        "    Properties:\n"
        "      Name: my-build\n"
        "      Environment:\n"
        "        Type: LINUX_CONTAINER\n"
        "        ComputeType: BUILD_GENERAL1_SMALL\n"
        "        Image: aws/codebuild/standard:7.0\n"
        "        EnvironmentVariables:\n"
        "          - Name: NPM_TOKEN\n"
        "            Type: SECRETS_MANAGER\n"
        "            Value: arn:aws:secretsmanager:us-east-1:123456789012:secret:npm-token-AbCdEf"
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [
        _cb001_plaintext_secrets(r.properties, r.address)
        for r in ctx.resources("AWS::CodeBuild::Project")
    ]
