"""GCS-003. Bucket versioning not enabled."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="GCS-003",
    title="Bucket versioning not enabled",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-494",),
    recommendation=(
        "Enable object versioning on the bucket. Combine with a "
        "lifecycle rule to delete old versions after a retention "
        "period to control storage costs."
    ),
    docs_note=(
        "Without versioning, overwritten or deleted objects are "
        "permanently lost. Versioning makes every write and delete "
        "recoverable, protecting against accidental or malicious "
        "artifact replacement."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for bucket in catalog.storage_buckets():
        name = bucket.get("name", "<unnamed>")
        passed = bool(bucket.get("versioning_enabled", False))
        if passed:
            desc = f"Bucket '{name}' has versioning enabled."
        else:
            desc = (
                f"Bucket '{name}' does not have versioning enabled. "
                "Overwritten or deleted objects are permanently lost."
            )
        findings.append(Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=name,
            description=desc,
            recommendation=RULE.recommendation,
            passed=passed,
        ))
    return findings
