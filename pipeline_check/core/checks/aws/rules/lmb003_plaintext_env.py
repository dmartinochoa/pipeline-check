"""LMB-003 — Lambda function env vars contain secret-like plaintext values."""
from __future__ import annotations

from ..._patterns import SECRET_NAME_RE, SECRET_VALUE_RE
from ...base import Finding, Severity
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
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=name, description=desc,
            recommendation=RULE.recommendation, passed=passed,
        ))
    return findings
