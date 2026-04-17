"""S3-004 — CodePipeline artifact bucket has server-access logging disabled."""
from __future__ import annotations

from botocore.exceptions import ClientError

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="S3-004",
    title="Artifact bucket access logging not enabled",
    severity=Severity.LOW,
    owasp=("CICD-SEC-10",),
    cwe=("CWE-778",),
    recommendation=(
        "Enable S3 server access logging for the artifact bucket and "
        "direct logs to a separate, centralised logging bucket with "
        "restricted write access."
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
            resp = s3.get_bucket_logging(Bucket=bucket)
            logging_enabled = "LoggingEnabled" in resp
        except ClientError as exc:
            findings.append(Finding(
                check_id=RULE.id, title=RULE.title, severity=RULE.severity,
                resource=bucket,
                description=f"Could not retrieve bucket logging config: {exc}",
                recommendation="Ensure s3:GetBucketLogging permission.",
                passed=False,
            ))
            continue
        if logging_enabled:
            target = resp["LoggingEnabled"].get("TargetBucket", "unknown")
            desc = f"Access logging is enabled; logs are delivered to '{target}'."
        else:
            desc = (
                "Server access logging is not enabled on the artifact bucket. "
                "Without access logs, it is not possible to audit who accessed, "
                "downloaded, or tampered with pipeline artifacts."
            )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=bucket, description=desc,
            recommendation=RULE.recommendation, passed=logging_enabled,
        ))
    return findings
