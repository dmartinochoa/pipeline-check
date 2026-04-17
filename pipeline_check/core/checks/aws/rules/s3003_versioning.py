"""S3-003 — CodePipeline artifact bucket has versioning disabled."""
from __future__ import annotations

from botocore.exceptions import ClientError

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="S3-003",
    title="Artifact bucket versioning not enabled",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-494",),
    recommendation=(
        "Enable S3 versioning on the artifact bucket so that previous "
        "artifact versions are retained and rollback is possible. Combine "
        "with a lifecycle rule to expire old versions after a retention period."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    buckets = catalog.s3_artifact_buckets()
    if not buckets:
        return findings
    s3 = catalog.client("s3")
    for bucket in buckets:
        try:
            resp = s3.get_bucket_versioning(Bucket=bucket)
            status = resp.get("Status", "")
            passed = status == "Enabled"
        except ClientError as exc:
            findings.append(Finding(
                check_id=RULE.id, title=RULE.title, severity=RULE.severity,
                resource=bucket,
                description=f"Could not retrieve bucket versioning status: {exc}",
                recommendation="Ensure s3:GetBucketVersioning permission.",
                passed=False,
            ))
            continue
        if passed:
            desc = "Versioning is enabled on the artifact bucket."
        else:
            desc = (
                "Versioning is not enabled on the artifact bucket. Without "
                "versioning, overwritten or deleted artifacts cannot be recovered, "
                "making it impossible to roll back to a known-good build artifact."
            )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=bucket, description=desc,
            recommendation=RULE.recommendation, passed=passed,
        ))
    return findings
