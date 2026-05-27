"""GCS-002. Bucket does not enforce uniform bucket-level access."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="GCS-002",
    title="Bucket does not enforce uniform bucket-level access",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-284",),
    recommendation=(
        "Enable uniform bucket-level access on the bucket. This "
        "disables object-level ACLs and enforces access exclusively "
        "through IAM, simplifying policy management and auditing."
    ),
    docs_note=(
        "Without uniform bucket-level access, objects can have "
        "individual ACLs that override bucket-level IAM policies. "
        "This creates an unauditable surface: a single object can "
        "be made public without changing the bucket policy."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for bucket in catalog.storage_buckets():
        name = bucket.get("name", "<unnamed>")
        iam_config = bucket.get("iam_configuration", {})
        ubla = iam_config.get("uniform_bucket_level_access", {})
        enabled = ubla.get("enabled", False)
        passed = bool(enabled)
        if passed:
            desc = f"Bucket '{name}' enforces uniform bucket-level access."
        else:
            desc = (
                f"Bucket '{name}' does not enforce uniform bucket-level "
                "access. Object-level ACLs can override the bucket's "
                "IAM policy."
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
