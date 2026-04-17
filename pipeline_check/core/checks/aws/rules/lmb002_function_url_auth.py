"""LMB-002 — Lambda function URL configured with AuthType=NONE."""
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
