"""GCS-004. Cloud Storage bucket not encrypted with CMEK."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="GCS-004",
    title="Cloud Storage bucket not encrypted with CMEK",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-311",),
    recommendation=(
        "Set a default Cloud KMS key on the bucket to use "
        "customer-managed encryption keys (CMEK). CMEK gives you "
        "control over the key lifecycle and access policy."
    ),
    docs_note=(
        "By default GCP encrypts bucket data with Google-managed keys. "
        "CMEK adds an additional layer of control: you can revoke "
        "access to stored data by disabling the key, and key usage "
        "appears in Cloud Audit Logs."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for bucket in catalog.storage_buckets():
        name = bucket.get("name", "<unnamed>")
        kms_key = bucket.get("default_kms_key_name")
        if kms_key:
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=name,
                description=(
                    f"Bucket '{name}' is encrypted with CMEK: "
                    f"{kms_key}."
                ),
                recommendation=RULE.recommendation,
                passed=True,
            ))
        else:
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=name,
                description=(
                    f"Bucket '{name}' uses Google-managed encryption. "
                    "No CMEK default key is configured."
                ),
                recommendation=RULE.recommendation,
                passed=False,
            ))
    return findings
