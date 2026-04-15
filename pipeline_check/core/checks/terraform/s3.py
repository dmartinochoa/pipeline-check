"""Terraform S3 checks (S3-001 … S3-004) — scoped to CodePipeline artifact buckets.

Terraform represents bucket configuration as separate helper resources joined
by bucket name:

    aws_s3_bucket
    aws_s3_bucket_public_access_block     (bucket = <name>)
    aws_s3_bucket_server_side_encryption_configuration
    aws_s3_bucket_versioning
    aws_s3_bucket_logging

Discovery: artifact bucket names are read from every ``aws_codepipeline``'s
``artifact_store[*].location``.
"""
from __future__ import annotations

from .base import TerraformBaseCheck
from ..base import Finding, Severity


def _first(block_list: list | None) -> dict:
    if not block_list:
        return {}
    return block_list[0] or {}


class S3Checks(TerraformBaseCheck):

    def run(self) -> list[Finding]:
        buckets = self._discover_artifact_buckets()
        if not buckets:
            return []

        pab = self._index_by_bucket("aws_s3_bucket_public_access_block")
        enc = self._index_by_bucket(
            "aws_s3_bucket_server_side_encryption_configuration"
        )
        ver = self._index_by_bucket("aws_s3_bucket_versioning")
        log = self._index_by_bucket("aws_s3_bucket_logging")

        findings: list[Finding] = []
        for bucket in sorted(buckets):
            findings.append(_s3001_pab(pab.get(bucket), bucket))
            findings.append(_s3002_encryption(enc.get(bucket), bucket))
            findings.append(_s3003_versioning(ver.get(bucket), bucket))
            findings.append(_s3004_logging(log.get(bucket), bucket))
        return findings

    def _discover_artifact_buckets(self) -> set[str]:
        buckets: set[str] = set()
        for r in self.ctx.resources("aws_codepipeline"):
            for store in r.values.get("artifact_store", []) or []:
                loc = store.get("location")
                if loc:
                    buckets.add(loc)
        return buckets

    def _index_by_bucket(self, resource_type: str) -> dict[str, dict]:
        out: dict[str, dict] = {}
        for r in self.ctx.resources(resource_type):
            bucket = r.values.get("bucket")
            if bucket:
                out[bucket] = r.values
        return out


def _s3001_pab(values: dict | None, bucket: str) -> Finding:
    if not values:
        fully_blocked = False
        missing = ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"]
    else:
        checks = {
            "BlockPublicAcls": bool(values.get("block_public_acls", False)),
            "IgnorePublicAcls": bool(values.get("ignore_public_acls", False)),
            "BlockPublicPolicy": bool(values.get("block_public_policy", False)),
            "RestrictPublicBuckets": bool(values.get("restrict_public_buckets", False)),
        }
        fully_blocked = all(checks.values())
        missing = [k for k, v in checks.items() if not v]

    desc = (
        "All four public access block settings are enabled on the artifact bucket."
        if fully_blocked else
        f"The following public access block settings are not enabled: {missing}. "
        f"Pipeline artifacts could be exposed publicly."
    )
    return Finding(
        check_id="S3-001",
        title="Artifact bucket public access block not fully enabled",
        severity=Severity.CRITICAL,
        resource=bucket,
        description=desc,
        recommendation=(
            "Attach an aws_s3_bucket_public_access_block resource with all "
            "four settings enabled."
        ),
        passed=fully_blocked,
    )


def _s3002_encryption(values: dict | None, bucket: str) -> Finding:
    encrypted = False
    algo = "unknown"
    if values:
        rules = values.get("rule", []) or []
        if rules:
            apply = _first(rules[0].get("apply_server_side_encryption_by_default"))
            algo = apply.get("sse_algorithm") or "unknown"
            encrypted = bool(algo and algo != "unknown")

    desc = (
        f"Artifact bucket is encrypted with {algo}."
        if encrypted else
        "No default server-side encryption is configured on the artifact bucket."
    )
    return Finding(
        check_id="S3-002",
        title="Artifact bucket server-side encryption not configured",
        severity=Severity.HIGH,
        resource=bucket,
        description=desc,
        recommendation=(
            "Add an aws_s3_bucket_server_side_encryption_configuration "
            "resource with at minimum AES256."
        ),
        passed=encrypted,
    )


def _s3003_versioning(values: dict | None, bucket: str) -> Finding:
    status = ""
    if values:
        vcfg = _first(values.get("versioning_configuration"))
        status = vcfg.get("status", "") or ""
    passed = status == "Enabled"
    desc = (
        "Versioning is enabled on the artifact bucket."
        if passed else
        "Versioning is not enabled on the artifact bucket. Overwritten or "
        "deleted artifacts cannot be recovered."
    )
    return Finding(
        check_id="S3-003",
        title="Artifact bucket versioning not enabled",
        severity=Severity.MEDIUM,
        resource=bucket,
        description=desc,
        recommendation=(
            "Add aws_s3_bucket_versioning with versioning_configuration.status "
            "= \"Enabled\"."
        ),
        passed=passed,
    )


def _s3004_logging(values: dict | None, bucket: str) -> Finding:
    target = (values or {}).get("target_bucket")
    enabled = bool(target)
    desc = (
        f"Access logging is enabled; logs are delivered to '{target}'."
        if enabled else
        "Server access logging is not enabled on the artifact bucket."
    )
    return Finding(
        check_id="S3-004",
        title="Artifact bucket access logging not enabled",
        severity=Severity.LOW,
        resource=bucket,
        description=desc,
        recommendation=(
            "Add an aws_s3_bucket_logging resource targeting a separate "
            "centralised logging bucket."
        ),
        passed=enabled,
    )
