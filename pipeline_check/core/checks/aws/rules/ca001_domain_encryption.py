"""CA-001 — CodeArtifact domain not encrypted with a customer KMS key."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="CA-001",
    title="CodeArtifact domain not encrypted with customer KMS CMK",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-311",),
    recommendation=(
        "Recreate the CodeArtifact domain with an encryption-key argument "
        "pointing at a customer-managed CMK. Domain encryption is set at "
        "creation and cannot be changed after."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for domain in catalog.codeartifact_domains():
        name = domain.get("name", "<unnamed>")
        key = domain.get("encryptionKey", "") or ""
        # AWS-owned keys use the ``alias/aws/codeartifact`` alias or are
        # unset. A CMK is any key whose ARN starts with ``arn:aws:kms:``
        # and is not the AWS-owned alias.
        passed = bool(key) and "alias/aws/" not in key
        desc = (
            f"Domain '{name}' is encrypted with {key}."
            if passed else
            f"Domain '{name}' uses AWS-owned encryption ({key or 'default'}); "
            "the key policy is not under your control."
        )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=name, description=desc,
            recommendation=RULE.recommendation, passed=passed,
        ))
    return findings
