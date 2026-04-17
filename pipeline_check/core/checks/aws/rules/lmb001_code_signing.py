"""LMB-001 — Lambda function has no code-signing config."""
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
