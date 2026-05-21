"""LMB-001. Lambda function has no code-signing config."""
from __future__ import annotations

from botocore.exceptions import ClientError

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="LMB-001",
    title="Lambda function has no code-signing config",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-347",),
    recommendation=(
        "Create an AWS Signer profile, reference it from an "
        "``aws_lambda_code_signing_config`` with ``untrusted_artifact_on_"
        "deployment = Enforce`` and attach that config to the function. "
        "Without one, the Lambda runtime will execute any code that a "
        "principal with lambda:UpdateFunctionCode uploads."
    ),
    docs_note=(
        "Lambda code-signing config + a Signer profile (SIGN-001) "
        "validates that an uploaded zip was signed by a known "
        "profile before it's allowed to run. Without one, anyone "
        "who reaches ``lambda:UpdateFunctionCode``, a CI/CD role "
        "compromise, a misattached IAM policy, can replace the "
        "function's code with no chain-of-custody check."
    ),
    exploit_example=(
        "# Vulnerable: a Lambda function with no CodeSigningConfig\n"
        "# attached. Anyone with ``lambda:UpdateFunctionCode`` can\n"
        "# push arbitrary code without signature verification; a\n"
        "# compromised deploy role ships malicious code into\n"
        "# production with no signing gate.\n"
        "import boto3\n"
        "lambdacli = boto3.client('lambda')\n"
        "lambdacli.get_function(FunctionName='process-payment')[\n"
        "    'Configuration'\n"
        "].get('CodeSigningConfigArn')  # -> None\n"
        "\n"
        "# Safe: create a Signing Profile + CodeSigningConfig\n"
        "# and attach it. Only signed code packages (signed via\n"
        "# AWS Signer) can be deployed; unsigned uploads are\n"
        "# rejected by Lambda.\n"
        "signer = boto3.client('signer')\n"
        "prof = signer.put_signing_profile(\n"
        "    profileName='prod-lambda-signer',\n"
        "    platformId='AWSLambda-SHA384-ECDSA',\n"
        ")\n"
        "csc = lambdacli.create_code_signing_config(\n"
        "    AllowedPublishers={'SigningProfileVersionArns': [prof['profileVersionArn']]},\n"
        "    CodeSigningPolicies={'UntrustedArtifactOnDeployment': 'Enforce'},\n"
        ")\n"
        "lambdacli.update_function_configuration(\n"
        "    FunctionName='process-payment',\n"
        "    CodeSigningConfigArn=csc['CodeSigningConfig']['CodeSigningConfigArn'],\n"
        ")"
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    client = catalog.client("lambda")
    for fn in catalog.lambda_functions():
        name = fn.get("FunctionName", "<unnamed>")
        try:
            resp = client.get_function_code_signing_config(FunctionName=name)
        except ClientError:
            # Treat "no config associated" the same as missing config.
            resp = {}
        arn = resp.get("CodeSigningConfigArn")
        passed = bool(arn)
        desc = (
            f"Function '{name}' requires signed artifacts (config {arn})."
            if passed else
            f"Function '{name}' has no code-signing config; unsigned "
            "uploads are deployable."
        )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=name, description=desc,
            recommendation=RULE.recommendation, passed=passed,
        ))
    return findings
