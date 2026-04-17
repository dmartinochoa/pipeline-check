"""S3-001 — CodePipeline artifact bucket public access block not fully enabled."""
from __future__ import annotations

from botocore.exceptions import ClientError

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="S3-001",
    title="Artifact bucket public access block not fully enabled",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-732",),
    recommendation=(
        "Enable all four S3 Block Public Access settings on the artifact "
        "bucket: BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, "
        "and RestrictPublicBuckets."
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
            resp = s3.get_public_access_block(Bucket=bucket)
            cfg = resp.get("PublicAccessBlockConfiguration", {}) or {}
            fully_blocked = all([
                cfg.get("BlockPublicAcls", False),
                cfg.get("IgnorePublicAcls", False),
                cfg.get("BlockPublicPolicy", False),
                cfg.get("RestrictPublicBuckets", False),
            ])
        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code", "")
            if error_code == "NoSuchPublicAccessBlockConfiguration":
                fully_blocked = False
                cfg = {}
            else:
                findings.append(Finding(
                    check_id=RULE.id, title=RULE.title, severity=RULE.severity,
                    resource=bucket,
                    description=f"Could not retrieve public access block config: {exc}",
                    recommendation="Ensure s3:GetBucketPublicAccessBlock permission.",
                    passed=False,
                ))
                continue
        if fully_blocked:
            desc = "All four public access block settings are enabled on the artifact bucket."
        else:
            missing = [
                k for k, v in {
                    "BlockPublicAcls": cfg.get("BlockPublicAcls", False),
                    "IgnorePublicAcls": cfg.get("IgnorePublicAcls", False),
                    "BlockPublicPolicy": cfg.get("BlockPublicPolicy", False),
                    "RestrictPublicBuckets": cfg.get("RestrictPublicBuckets", False),
                }.items()
                if not v
            ]
            desc = (
                f"The following public access block settings are not enabled: "
                f"{missing}. Pipeline artifacts could be exposed publicly if a "
                f"bucket ACL or policy is accidentally permissive."
            )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=bucket, description=desc,
            recommendation=RULE.recommendation, passed=fully_blocked,
        ))
    return findings
