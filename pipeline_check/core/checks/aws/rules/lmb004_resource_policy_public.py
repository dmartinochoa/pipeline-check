"""LMB-004. Lambda function resource policy grants wildcard principal."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from ..._iam_policy import iter_allow, public_principal
from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="LMB-004",
    title="Lambda resource policy allows wildcard principal",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-8",),
    cwe=("CWE-732",),
    recommendation=(
        "Remove Allow statements with ``Principal: '*'`` from every "
        "Lambda function resource policy, or scope them with a "
        "``SourceArn`` / ``SourceAccount`` condition. Service principals "
        "(e.g. ``apigateway.amazonaws.com``) are the common legitimate "
        "case, ensure they carry a condition."
    ),
    docs_note=(
        "A wildcard-principal Allow on a Lambda function resource "
        "policy lets anyone invoke. The legitimate case is a "
        "service principal (API Gateway, S3 events) where AWS "
        "fills in the SourceArn/SourceAccount at invoke time, "
        "without those conditions, any account using that service "
        "can invoke."
    ),
    exploit_example=(
        "# Vulnerable: any AWS account on the internet can invoke\n"
        "# this function. If the function reads from S3, writes to\n"
        "# DynamoDB, or calls a downstream service, the attacker\n"
        "# gets that downstream authority at whatever rate they're\n"
        "# willing to pay for the invocations.\n"
        "{\n"
        '  "Version": "2012-10-17",\n'
        '  "Statement": [{\n'
        '    "Sid": "AllowAnyoneToInvoke",\n'
        '    "Effect": "Allow",\n'
        '    "Principal": "*",\n'
        '    "Action": "lambda:InvokeFunction",\n'
        '    "Resource": "arn:aws:lambda:us-east-1:123456789012:function:my-fn"\n'
        "  }]\n"
        "}\n"
        "\n"
        "# Safe: keep the service-principal binding (API Gateway,\n"
        "# S3 events, etc.) but pair it with a SourceArn or\n"
        "# SourceAccount Condition so AWS rejects invokes that\n"
        "# don't originate from the expected upstream.\n"
        "{\n"
        '  "Version": "2012-10-17",\n'
        '  "Statement": [{\n'
        '    "Effect": "Allow",\n'
        '    "Principal": {"Service": "apigateway.amazonaws.com"},\n'
        '    "Action": "lambda:InvokeFunction",\n'
        '    "Resource": "arn:aws:lambda:us-east-1:123456789012:function:my-fn",\n'
        '    "Condition": {\n'
        '      "ArnLike": {\n'
        '        "AWS:SourceArn": "arn:aws:execute-api:us-east-1:123456789012:abc123/*"\n'
        "      }\n"
        "    }\n"
        "  }]\n"
        "}"
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    client = catalog.client("lambda")
    for fn in catalog.lambda_functions():
        name = fn.get("FunctionName", "<unnamed>")
        try:
            resp = client.get_policy(FunctionName=name)
        except ClientError:
            continue  # no policy = no exposure
        raw = resp.get("Policy")
        if not raw:
            continue
        try:
            doc = json.loads(raw) if isinstance(raw, str) else raw
        except (TypeError, json.JSONDecodeError):
            continue
        offenders: list[int] = []
        for idx, stmt in enumerate(iter_allow(doc)):
            if not public_principal(stmt):
                continue
            # If the statement has a SourceArn / SourceAccount condition,
            # the wildcard is effectively scoped. A non-dict Condition
            # (malformed policy) carries no scoping keys.
            cond_raw = stmt.get("Condition")
            conditions = cond_raw if isinstance(cond_raw, dict) else {}
            scoped = any(
                any(
                    isinstance(key, str) and key.lower() in ("aws:sourcearn", "aws:sourceaccount")
                    for key in (inner or {})
                )
                for inner in conditions.values()
                if isinstance(inner, dict)
            )
            if not scoped:
                offenders.append(idx)
        passed = not offenders
        desc = (
            f"Function '{name}' policy has no unscoped wildcard Allow."
            if passed else
            f"Function '{name}' policy Allow statement(s) {offenders} "
            "grant Principal: '*' without a SourceArn/SourceAccount condition."
        )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=name, description=desc,
            recommendation=RULE.recommendation, passed=passed,
        ))
    return findings
