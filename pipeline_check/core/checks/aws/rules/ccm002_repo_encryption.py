"""CCM-002 — CodeCommit repository not encrypted with a customer KMS key."""
from __future__ import annotations

from botocore.exceptions import ClientError

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="CCM-002",
    title="CodeCommit repository not encrypted with customer KMS CMK",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-311",),
    recommendation=(
        "Recreate the repository with a ``kmsKeyId`` argument pointing at "
        "a customer-managed KMS key. CodeCommit encryption is set at "
        "creation and cannot be changed afterwards."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    client = catalog.client("codecommit")
    for repo_summary in catalog.codecommit_repositories():
        name = repo_summary.get("repositoryName", "<unnamed>")
        try:
            detail = client.get_repository(repositoryName=name)
        except ClientError:
            continue
        key = (detail.get("repositoryMetadata") or {}).get("kmsKeyId", "") or ""
        passed = bool(key) and "alias/aws/codecommit" not in key
        desc = (
            f"Repo '{name}' is encrypted with KMS key {key}."
            if passed else
            f"Repo '{name}' uses AWS-owned encryption; the key policy is "
            "not under your control."
        )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=name, description=desc,
            recommendation=RULE.recommendation, passed=passed,
        ))
    return findings
