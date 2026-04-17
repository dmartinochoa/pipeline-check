"""CWL-002 — CodeBuild log groups are not KMS-encrypted."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="CWL-002",
    title="CodeBuild log group not KMS-encrypted",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-311",),
    recommendation=(
        "Associate a customer-managed KMS key with every "
        "``/aws/codebuild/*`` log group via ``associate-kms-key``. Logs "
        "often contain secret material accidentally echoed by builds; "
        "encrypting them with a CMK means the key policy controls who can "
        "read the logs, not just S3/CloudWatch IAM."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for lg in catalog.log_groups("/aws/codebuild/"):
        name = lg.get("logGroupName", "<unnamed>")
        kms = lg.get("kmsKeyId")
        passed = bool(kms)
        if passed:
            desc = f"Log group '{name}' is encrypted with KMS key {kms}."
        else:
            desc = (
                f"Log group '{name}' uses default AWS-owned encryption. Any "
                "principal with logs:GetLogEvents can read the contents."
            )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=name, description=desc,
            recommendation=RULE.recommendation, passed=passed,
        ))
    return findings
