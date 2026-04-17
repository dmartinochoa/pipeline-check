"""SSM-002 — SecureString parameter uses default ``alias/aws/ssm`` key instead of CMK."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="SSM-002",
    title="SSM SecureString uses the default AWS-managed key",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-311",),
    recommendation=(
        "Recreate SecureString parameters with ``KeyId`` pointing at a "
        "customer-managed KMS key. The default ``alias/aws/ssm`` key is "
        "shared across the account and its key policy cannot be audited "
        "or scoped per parameter."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for param in catalog.ssm_parameters():
        if param.get("Type") != "SecureString":
            continue
        name = param.get("Name", "<unnamed>")
        key_id = param.get("KeyId", "") or ""
        passed = bool(key_id) and "alias/aws/ssm" not in key_id
        desc = (
            f"Parameter '{name}' is encrypted with CMK {key_id}."
            if passed else
            f"Parameter '{name}' is encrypted with the AWS-managed key "
            f"({key_id or 'alias/aws/ssm'}); key policy is not under your control."
        )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=name, description=desc,
            recommendation=RULE.recommendation, passed=passed,
        ))
    return findings
