"""ECR-005 — ECR repository uses AES256 (AWS-managed) encryption, not KMS CMK."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="ECR-005",
    title="Repository encrypted with AES256 rather than KMS CMK",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-311",),
    recommendation=(
        "Set encryptionType=KMS with a customer-managed key ARN."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for repo in catalog.ecr_repositories():
        name = repo.get("repositoryName", "<unnamed>")
        cfg = repo.get("encryptionConfiguration", {}) or {}
        enc_type = cfg.get("encryptionType") or "AES256"
        kms_key = cfg.get("kmsKey")
        passed = enc_type == "KMS" and bool(kms_key)
        desc = (
            f"Repository uses KMS encryption with key {kms_key}."
            if passed else
            f"Repository encryptionType is {enc_type!r}. AES256 uses an "
            f"AWS-managed key, which cannot be audited or restricted via key policies."
        )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=name, description=desc,
            recommendation=RULE.recommendation, passed=passed,
        ))
    return findings
