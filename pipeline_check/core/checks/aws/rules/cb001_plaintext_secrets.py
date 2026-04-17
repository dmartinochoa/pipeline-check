"""CB-001 — Secrets in plaintext CodeBuild environment variables."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..._patterns import SECRET_NAME_RE, SECRET_VALUE_RE
from .._catalog import ResourceCatalog

RULE = Rule(
    id="CB-001",
    title="Secrets in plaintext environment variables",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-6",),
    cwe=("CWE-798",),
    recommendation=(
        "Move secrets to AWS Secrets Manager or SSM Parameter Store and "
        "reference them using type SECRETS_MANAGER or PARAMETER_STORE in "
        "the CodeBuild environment variable configuration."
    ),
    docs_note=(
        "Flags a plaintext env var when either (a) its **name** matches a "
        "secret-like pattern (PASSWORD, TOKEN, API_KEY, ...) or (b) its "
        "**value** matches a known credential shape (AKIA/ASIA access "
        "keys, GitHub tokens, Slack xox* tokens, JWTs). Plaintext values "
        "are visible in the AWS console, CloudTrail, and build logs to "
        "anyone with read access."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for project in catalog.codebuild_projects():
        name = project.get("name", "<unnamed>")
        env_vars = project.get("environment", {}).get("environmentVariables", [])
        suspicious_names: list[str] = []
        suspicious_values: list[str] = []
        for v in env_vars:
            if v.get("type", "PLAINTEXT") != "PLAINTEXT":
                continue
            vname = v.get("name", "")
            vval = v.get("value", "") or ""
            if SECRET_NAME_RE.search(vname):
                suspicious_names.append(vname)
            elif isinstance(vval, str) and SECRET_VALUE_RE.match(vval):
                suspicious_values.append(vname or "<unnamed>")
        passed = not (suspicious_names or suspicious_values)
        if passed:
            desc = "No plaintext environment variables with secret-like names or values detected."
        else:
            parts = []
            if suspicious_names:
                parts.append(f"secret-like names: {', '.join(suspicious_names)}")
            if suspicious_values:
                parts.append(
                    f"credential-like values under: {', '.join(suspicious_values)}"
                )
            desc = (
                f"Plaintext environment variables appear to contain secrets "
                f"({'; '.join(parts)})."
            )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=name, description=desc,
            recommendation=RULE.recommendation, passed=passed,
        ))
    return findings
