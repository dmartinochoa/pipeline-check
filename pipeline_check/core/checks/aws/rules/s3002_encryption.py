"""S3-002 — CodePipeline artifact bucket has no default server-side encryption."""
from __future__ import annotations

from botocore.exceptions import ClientError

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="S3-002",
    title="Artifact bucket server-side encryption not configured",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-311",),
    recommendation=(
        "Enable default bucket encryption using at minimum AES256 (SSE-S3). "
        "For stronger key control, use SSE-KMS with a customer-managed key."
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
            resp = s3.get_bucket_encryption(Bucket=bucket)
            rules = (
                resp.get("ServerSideEncryptionConfiguration", {})
                .get("Rules", [])
            )
            encrypted = len(rules) > 0
        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code", "")
            if error_code in (
                "ServerSideEncryptionConfigurationNotFoundError",
                "NoSuchBucket",
            ):
                encrypted = False
                rules = []
            else:
                findings.append(Finding(
                    check_id=RULE.id, title=RULE.title, severity=RULE.severity,
                    resource=bucket,
                    description=f"Could not retrieve bucket encryption config: {exc}",
                    recommendation="Ensure s3:GetEncryptionConfiguration permission.",
                    passed=False,
                ))
                continue
        if encrypted:
            algo = rules[0].get("ApplyServerSideEncryptionByDefault", {}).get(
                "SSEAlgorithm", "unknown"
            )
            desc = f"Artifact bucket is encrypted with {algo}."
        else:
            desc = (
                "No default server-side encryption is configured on the artifact "
                "bucket. Pipeline artifacts (source zips, compiled binaries) are "
                "stored unencrypted at rest."
            )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=bucket, description=desc,
            recommendation=RULE.recommendation, passed=encrypted,
        ))
    return findings
