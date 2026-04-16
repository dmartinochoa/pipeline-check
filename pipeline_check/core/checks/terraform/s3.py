"""Terraform S3 checks — scoped to CodePipeline artifact buckets.

S3-001  Public access block not fully enabled       CRITICAL  CICD-SEC-9
S3-002  Server-side encryption not configured       HIGH      CICD-SEC-9
S3-003  Versioning not enabled                      MEDIUM    CICD-SEC-9
S3-004  Access logging not enabled                  LOW       CICD-SEC-10
S3-005  Bucket policy missing aws:SecureTransport   MEDIUM    CICD-SEC-9
"""
from __future__ import annotations

import json

from ..base import Finding, Severity
from .base import TerraformBaseCheck


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
        enc = self._index_by_bucket("aws_s3_bucket_server_side_encryption_configuration")
        ver = self._index_by_bucket("aws_s3_bucket_versioning")
        log = self._index_by_bucket("aws_s3_bucket_logging")
        pol = self._index_by_bucket("aws_s3_bucket_policy")

        findings: list[Finding] = []
        for bucket in sorted(buckets):
            findings.append(_s3001_pab(pab.get(bucket), bucket))
            findings.append(_s3002_encryption(enc.get(bucket), bucket))
            findings.append(_s3003_versioning(ver.get(bucket), bucket))
            findings.append(_s3004_logging(log.get(bucket), bucket))
            findings.append(_s3005_secure_transport(pol.get(bucket), bucket))
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
        "All four public access block settings are enabled."
        if fully_blocked else
        f"Missing: {missing}."
    )
    return Finding(
        check_id="S3-001",
        title="Artifact bucket public access block not fully enabled",
        severity=Severity.CRITICAL,
        resource=bucket,
        description=desc,
        recommendation="Attach aws_s3_bucket_public_access_block with all four flags true.",
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
        "No default server-side encryption is configured."
    )
    return Finding(
        check_id="S3-002",
        title="Artifact bucket server-side encryption not configured",
        severity=Severity.HIGH,
        resource=bucket,
        description=desc,
        recommendation="Add aws_s3_bucket_server_side_encryption_configuration.",
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
        "Versioning is not enabled on the artifact bucket."
    )
    return Finding(
        check_id="S3-003",
        title="Artifact bucket versioning not enabled",
        severity=Severity.MEDIUM,
        resource=bucket,
        description=desc,
        recommendation="Add aws_s3_bucket_versioning with status = \"Enabled\".",
        passed=passed,
    )


def _s3004_logging(values: dict | None, bucket: str) -> Finding:
    target = (values or {}).get("target_bucket")
    enabled = bool(target)
    desc = (
        f"Access logging is enabled; logs delivered to '{target}'."
        if enabled else
        "Server access logging is not enabled."
    )
    return Finding(
        check_id="S3-004",
        title="Artifact bucket access logging not enabled",
        severity=Severity.LOW,
        resource=bucket,
        description=desc,
        recommendation="Add aws_s3_bucket_logging targeting a central logging bucket.",
        passed=enabled,
    )


def _s3005_secure_transport(values: dict | None, bucket: str) -> Finding:
    policy_text = (values or {}).get("policy") or ""
    if not policy_text:
        return Finding(
            check_id="S3-005",
            title="Artifact bucket missing aws:SecureTransport deny",
            severity=Severity.MEDIUM,
            resource=bucket,
            description=(
                "No bucket policy is attached, so plaintext HTTP requests are "
                "not explicitly denied."
            ),
            recommendation=(
                "Attach an aws_s3_bucket_policy that Denies s3:* when "
                "aws:SecureTransport is false."
            ),
            passed=False,
        )

    try:
        doc = json.loads(policy_text) if isinstance(policy_text, str) else policy_text
    except (TypeError, json.JSONDecodeError):
        doc = {}

    has_deny = False
    for stmt in doc.get("Statement", []):
        if stmt.get("Effect") != "Deny":
            continue
        conditions = stmt.get("Condition", {}) or {}
        for operator_block in conditions.values():
            if not isinstance(operator_block, dict):
                continue
            if str(operator_block.get("aws:SecureTransport", "")).lower() == "false":
                has_deny = True
                break
        if has_deny:
            break

    desc = (
        "Bucket policy denies non-TLS requests via aws:SecureTransport."
        if has_deny else
        "Bucket policy does not include a Deny statement for requests where "
        "aws:SecureTransport is false. HTTP requests can read or write artifacts."
    )
    return Finding(
        check_id="S3-005",
        title="Artifact bucket missing aws:SecureTransport deny",
        severity=Severity.MEDIUM,
        resource=bucket,
        description=desc,
        recommendation=(
            "Add a Deny statement to the bucket policy that matches s3:* with "
            "a Bool condition aws:SecureTransport = false."
        ),
        passed=has_deny,
    )
