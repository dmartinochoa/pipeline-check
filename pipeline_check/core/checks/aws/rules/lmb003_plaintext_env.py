"""LMB-003. Lambda function env vars contain secret-like plaintext values."""
from __future__ import annotations

from ..._patterns import SECRET_NAME_RE, SECRET_VALUE_RE
from ..._primitives.anchors import iam_role, lambda_fn
from ...base import Finding, ResourceAnchor, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

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
            if SECRET_NAME_RE.search(k):
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
