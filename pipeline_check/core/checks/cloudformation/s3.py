"""CloudFormation S3 checks — scoped to CodePipeline artifact buckets.

CFN collapses most of Terraform's separate S3 resources into inline
properties on ``AWS::S3::Bucket``:

  - ``PublicAccessBlockConfiguration``
  - ``BucketEncryption.ServerSideEncryptionConfiguration``
  - ``VersioningConfiguration``
  - ``LoggingConfiguration``

``AWS::S3::BucketPolicy`` stays a separate resource.

Pipelines reference their artifact bucket via
``ArtifactStore.Location``, which is usually ``{"Ref": "MyBucket"}``
so the bucket is identified by its logical id rather than name.
"""
from __future__ import annotations

import json

from ..base import Finding, Severity
from .base import CloudFormationBaseCheck, CloudFormationResource, as_str


class S3Checks(CloudFormationBaseCheck):

    def run(self) -> list[Finding]:
        targets = self._discover_artifact_buckets()
        if not targets:
            return []

        # Build a lookup from {literal-bucket-name, logical-id} → Bucket
        # resource so we can find the configuration for whichever form
        # the pipeline's ArtifactStore.Location used.
        bucket_by_name: dict[str, CloudFormationResource] = {}
        for b in self.ctx.resources("AWS::S3::Bucket"):
            if lit := as_str(b.properties.get("BucketName")):
                bucket_by_name[lit] = b
            bucket_by_name[b.logical_id] = b

        policies_by_bucket: dict[str, dict] = {}
        for p in self.ctx.resources("AWS::S3::BucketPolicy"):
            target = p.properties.get("Bucket")
            key = _target_key(target)
            if key:
                policies_by_bucket[key] = p.properties

        findings: list[Finding] = []
        for tgt in sorted(targets):
            bucket = bucket_by_name.get(tgt)
            props = bucket.properties if bucket else {}
            bucket_name = as_str(props.get("BucketName")) or tgt
            findings.append(_s3001_pab(props, bucket_name))
            findings.append(_s3002_encryption(props, bucket_name))
            findings.append(_s3003_versioning(props, bucket_name))
            findings.append(_s3004_logging(props, bucket_name))
            policy_props = policies_by_bucket.get(tgt) or policies_by_bucket.get(bucket_name) or {}
            findings.append(_s3005_secure_transport(policy_props, bucket_name))
        return findings

    def _discover_artifact_buckets(self) -> set[str]:
        out: set[str] = set()
        for r in self.ctx.resources("AWS::CodePipeline::Pipeline"):
            single = r.properties.get("ArtifactStore") or {}
            key = _target_key(single.get("Location"))
            if key:
                out.add(key)
            plural = r.properties.get("ArtifactStores") or []
            if isinstance(plural, list):
                for entry in plural:
                    if not isinstance(entry, dict):
                        continue
                    store = entry.get("ArtifactStore") or {}
                    key = _target_key(store.get("Location"))
                    if key:
                        out.add(key)
        return out


def _target_key(value) -> str:
    """Normalise a bucket reference to either a literal name or logical id."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        if "Ref" in value:
            return value["Ref"]
        if "Fn::GetAtt" in value:
            att = value["Fn::GetAtt"]
            if isinstance(att, list) and att:
                return att[0]
    return ""


def _s3001_pab(props: dict, bucket: str) -> Finding:
    pab = props.get("PublicAccessBlockConfiguration") or {}
    checks = {
        "BlockPublicAcls": bool(pab.get("BlockPublicAcls")),
        "IgnorePublicAcls": bool(pab.get("IgnorePublicAcls")),
        "BlockPublicPolicy": bool(pab.get("BlockPublicPolicy")),
        "RestrictPublicBuckets": bool(pab.get("RestrictPublicBuckets")),
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
        recommendation="Set PublicAccessBlockConfiguration with all four flags true.",
        passed=fully_blocked,
    )


def _s3002_encryption(props: dict, bucket: str) -> Finding:
    enc = props.get("BucketEncryption") or {}
    rules = enc.get("ServerSideEncryptionConfiguration") or []
    encrypted = False
    algo = "unknown"
    if rules and isinstance(rules[0], dict):
        sse = rules[0].get("ServerSideEncryptionByDefault") or {}
        algo = as_str(sse.get("SSEAlgorithm")) or "unknown"
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
        recommendation="Set BucketEncryption.ServerSideEncryptionConfiguration.",
        passed=encrypted,
    )


def _s3003_versioning(props: dict, bucket: str) -> Finding:
    vcfg = props.get("VersioningConfiguration") or {}
    status = as_str(vcfg.get("Status"))
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
        recommendation='Set VersioningConfiguration.Status: "Enabled".',
        passed=passed,
    )


def _s3004_logging(props: dict, bucket: str) -> Finding:
    logging = props.get("LoggingConfiguration") or {}
    target = logging.get("DestinationBucketName")
    enabled = bool(target)
    desc = (
        f"Access logging is enabled; logs delivered to {target!r}."
        if enabled else
        "Server access logging is not enabled."
    )
    return Finding(
        check_id="S3-004",
        title="Artifact bucket access logging not enabled",
        severity=Severity.LOW,
        resource=bucket,
        description=desc,
        recommendation="Set LoggingConfiguration.DestinationBucketName.",
        passed=enabled,
    )


def _s3005_secure_transport(policy_props: dict, bucket: str) -> Finding:
    policy_doc = policy_props.get("PolicyDocument") if policy_props else None
    if not policy_doc:
        return Finding(
            check_id="S3-005",
            title="Artifact bucket missing aws:SecureTransport deny",
            severity=Severity.MEDIUM,
            resource=bucket,
            description=(
                "No AWS::S3::BucketPolicy references this bucket, so HTTP "
                "requests are not explicitly denied."
            ),
            recommendation=(
                "Attach an AWS::S3::BucketPolicy that Denies s3:* when "
                "aws:SecureTransport is false."
            ),
            passed=False,
        )
    if isinstance(policy_doc, str):
        try:
            doc = json.loads(policy_doc)
        except (TypeError, json.JSONDecodeError):
            doc = {}
    elif isinstance(policy_doc, dict):
        doc = policy_doc
    else:
        doc = {}
    has_deny = False
    for stmt in doc.get("Statement", []):
        if not isinstance(stmt, dict) or stmt.get("Effect") != "Deny":
            continue
        conditions = stmt.get("Condition") or {}
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
        "aws:SecureTransport is false."
    )
    return Finding(
        check_id="S3-005",
        title="Artifact bucket missing aws:SecureTransport deny",
        severity=Severity.MEDIUM,
        resource=bucket,
        description=desc,
        recommendation=(
            "Add a Deny statement to the bucket policy with a Bool condition "
            "aws:SecureTransport = false."
        ),
        passed=has_deny,
    )
