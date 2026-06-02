"""LMB-003. Lambda function env vars contain secret-like plaintext values."""
from __future__ import annotations

import re

from ..._patterns import SECRET_NAME_RE, SECRET_VALUE_RE
from ..._primitives.anchors import iam_role, lambda_fn
from ...base import Finding, ResourceAnchor, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

# Env-var names ending in these suffixes store a *reference* to a secret
# (ARN, parameter name, path, etc.) rather than the secret value itself.
# ``DB_SECRET_ARN``, ``API_KEY_SECRET_ARN``, ``TOKEN_NAME``, ``PASSWORD_PATH``
# are all the AWS-recommended pattern for Lambda functions that retrieve the
# real credential at runtime via Secrets Manager / SSM Parameter Store.
# We skip the name-based heuristic for these; the value-based detector still
# runs so a genuine plaintext credential stored under such a key will fire.
_REFERENCE_SUFFIX_RE = re.compile(
    r"_(?:ARN|NAME|PARAM|PATH|REF)$",
    re.IGNORECASE,
)

RULE = Rule(
    id="LMB-003",
    title="Lambda function env vars may contain plaintext secrets",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6",),
    cwe=("CWE-798",),
    recommendation=(
        "Move secrets out of Lambda environment variables and into Secrets "
        "Manager or SSM Parameter Store. Environment variables are visible "
        "to anyone with ``lambda:GetFunctionConfiguration`` and persist in "
        "CloudTrail events, which keeps the secret in audit logs."
    ),
    docs_note=(
        "Lambda env vars are world-readable to any principal with "
        "``lambda:GetFunctionConfiguration``, much wider than the "
        "principal that can invoke the function. They also persist "
        "in CloudFormation drift, change-sets, and CloudTrail "
        "events. A secret in a Lambda env var is essentially "
        "exposed to anyone with read access to the account."
    ),
    exploit_example=(
        "# Vulnerable: a Lambda function carries credentials in\n"
        "# its environment variables in plaintext. The values\n"
        "# are visible to anyone with ``lambda:GetFunction``\n"
        "# (a wider permission than secrets-manager access),\n"
        "# logged into CloudTrail, and lifted into\n"
        "# ``UpdateFunctionConfiguration`` events.\n"
        "import boto3\n"
        "lambdacli = boto3.client('lambda')\n"
        "lambdacli.update_function_configuration(\n"
        "    FunctionName='process-payment',\n"
        "    Environment={'Variables': {\n"
        "        'DB_PASSWORD': 'hunter2-prod-pw',\n"
        "        'API_KEY': 'sk_live_abc123def456ghi789',\n"
        "    }},\n"
        ")\n"
        "\n"
        "# Safe: store credentials in Secrets Manager and fetch\n"
        "# them at runtime via the Lambda's role. Env carries\n"
        "# only the secret's name / ARN, not the value.\n"
        "lambdacli.update_function_configuration(\n"
        "    FunctionName='process-payment',\n"
        "    Environment={'Variables': {\n"
        "        'DB_SECRET_ARN': 'arn:aws:secretsmanager:us-east-1:123:secret:prod/db-AbCdEf',\n"
        "        'API_KEY_SECRET_ARN': 'arn:aws:secretsmanager:us-east-1:123:secret:prod/api-Ab2Cd3',\n"
        "    }},\n"
        ")"
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for fn in catalog.lambda_functions():
        name = fn.get("FunctionName", "<unnamed>")
        env = (fn.get("Environment") or {}).get("Variables") or {}
        suspicious_names: list[str] = []
        suspicious_values: list[str] = []
        for k, v in env.items():
            if not isinstance(k, str):
                continue
            if SECRET_NAME_RE.search(k) and not _REFERENCE_SUFFIX_RE.search(k):
                suspicious_names.append(k)
            elif isinstance(v, str) and SECRET_VALUE_RE.match(v):
                suspicious_values.append(k)
        passed = not (suspicious_names or suspicious_values)
        if passed:
            desc = f"Function '{name}' env vars have no secret-like names or values."
        else:
            parts = []
            if suspicious_names:
                parts.append(f"secret-like names: {', '.join(suspicious_names)}")
            if suspicious_values:
                parts.append(f"credential-like values under: {', '.join(suspicious_values)}")
            desc = f"Function '{name}' env vars look suspicious ({'; '.join(parts)})."
        # ResourceAnchor phase 1: emit the function's own ARN plus its
        # execution-role ARN. AC-019 intersects the execution-role
        # anchor with IAM-004's CI-role anchor — when they match, the
        # secret-leaking Lambda is itself running with the wildcard-
        # PassRole role, which is the tight reachability claim (anyone
        # who exfils the env var inherits the role-hop primitive in
        # the same execution context). The function ARN is emitted so
        # future cross-provider chains keyed on lambda_fn can match.
        anchors: list[ResourceAnchor] = []
        fn_arn = fn.get("FunctionArn")
        if isinstance(fn_arn, str):
            built_fn = lambda_fn(fn_arn)
            if built_fn is not None:
                anchors.append(built_fn)
        role_arn = fn.get("Role")
        if isinstance(role_arn, str):
            built_role = iam_role(role_arn)
            if built_role is not None:
                anchors.append(built_role)
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=name, description=desc,
            recommendation=RULE.recommendation, passed=passed,
            resource_anchors=tuple(anchors),
        ))
    return findings
