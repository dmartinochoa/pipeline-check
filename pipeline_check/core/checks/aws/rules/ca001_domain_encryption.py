"""CA-001. CodeArtifact domain not encrypted with a customer KMS key."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="CA-001",
    title="CodeArtifact domain has no KMS encryptionKey configured",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-311",),
    recommendation=(
        "Recreate the CodeArtifact domain with an encryption-key argument "
        "pointing at a customer-managed CMK. Domain encryption is set at "
        "creation and cannot be changed after."
    ),
    docs_note=(
        "When no ``encryptionKey`` is configured on the domain, AWS uses "
        "its own managed key, keeping the key policy under AWS's control. "
        "That removes your ability to scope or audit Decrypt operations, "
        "and you can't revoke key access without recreating the domain. "
        "A customer-managed CMK puts those controls back in your hands. "
        "Note: the CodeArtifact API returns the resolved KMS key ARN in "
        "this field; the check flags only the absent-key case because the "
        "ARN alone does not reliably identify whether the key is AWS-managed "
        "or customer-managed without a separate ``kms:DescribeKey`` call."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for domain in catalog.codeartifact_domains():
        name = domain.get("name", "<unnamed>")
        key = domain.get("encryptionKey", "") or ""
        # Flag only when no encryptionKey is configured at all. The
        # CodeArtifact API returns the resolved KMS key ARN (not the alias
        # string), so the previous ``"alias/aws/" not in key`` check would
        # silently pass a domain using the AWS-managed default key once it
        # has been resolved to an ARN. Flagging the absent-key case is safe
        # and accurate; distinguishing CMK from AWS-managed would require a
        # separate kms:DescribeKey call that the catalog does not support.
        passed = bool(key)
        desc = (
            f"Domain '{name}' has an encryptionKey configured ({key})."
            if passed else
            f"Domain '{name}' has no encryptionKey configured; "
            "AWS-owned encryption is in use and the key policy is not under your control."
        )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=name, description=desc,
            recommendation=RULE.recommendation, passed=passed,
        ))
    return findings
