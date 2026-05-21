"""LMB-002. Lambda function URL configured with AuthType=NONE."""
from __future__ import annotations

from botocore.exceptions import ClientError

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="LMB-002",
    title="Lambda function URL has AuthType=NONE",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-8",),
    cwe=("CWE-306",),
    recommendation=(
        "Set the function URL ``auth_type`` to ``AWS_IAM`` and grant "
        "``lambda:InvokeFunctionUrl`` through IAM. ``NONE`` exposes the "
        "function to the public internet without authentication."
    ),
    docs_note=(
        "A Lambda function URL with ``AuthType=NONE`` is a public "
        "HTTPS endpoint. Anyone who knows the URL can invoke. This "
        "is sometimes deliberate (a webhook receiver) but the "
        "deliberate version typically signs / validates inside the "
        "function, the rule fires regardless because the IAM-side "
        "control isn't there."
    ),
    exploit_example=(
        "# Vulnerable: a Lambda Function URL with\n"
        "# ``AuthType: NONE``. The URL is on the public internet\n"
        "# and requires no authentication. Anyone who learns the\n"
        "# URL can invoke the function (and any downstream\n"
        "# service it can reach); functions that read from RDS\n"
        "# or write to S3 become a free Internet -> AWS-internal\n"
        "# bridge.\n"
        "import boto3\n"
        "lambdacli = boto3.client('lambda')\n"
        "lambdacli.create_function_url_config(\n"
        "    FunctionName='process-payment',\n"
        "    AuthType='NONE',\n"
        ")\n"
        "\n"
        "# Safe: ``AuthType: AWS_IAM`` requires the caller to\n"
        "# sign the request with IAM credentials. The URL is\n"
        "# still reachable from the internet, but only IAM\n"
        "# principals with ``lambda:InvokeFunctionUrl`` on the\n"
        "# function can call it.\n"
        "lambdacli.update_function_url_config(\n"
        "    FunctionName='process-payment',\n"
        "    AuthType='AWS_IAM',\n"
        ")"
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    client = catalog.client("lambda")
    for fn in catalog.lambda_functions():
        name = fn.get("FunctionName", "<unnamed>")
        try:
            url_cfg = client.get_function_url_config(FunctionName=name)
        except ClientError:
            continue  # no URL configured
        auth = url_cfg.get("AuthType", "")
        passed = auth == "AWS_IAM"
        desc = (
            f"Function '{name}' URL requires AWS_IAM."
            if passed else
            f"Function '{name}' URL AuthType is {auth or 'unset'}; the "
            "function is reachable anonymously."
        )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=name, description=desc,
            recommendation=RULE.recommendation, passed=passed,
        ))
    return findings
