"""S3 security checks (scoped to CodePipeline artifact buckets).

Discovers artifact bucket names from CodePipeline configurations so checks
are scoped to CI/CD-relevant buckets only.

S3-001  Artifact bucket public access block not fully enabled  CRITICAL  CICD-SEC-9
S3-002  Artifact bucket server-side encryption not configured  HIGH      CICD-SEC-9
S3-003  Artifact bucket versioning not enabled                 MEDIUM    CICD-SEC-9
S3-004  Artifact bucket access logging not enabled             LOW       CICD-SEC-10
S3-005  Artifact bucket missing aws:SecureTransport deny       MEDIUM    CICD-SEC-9
"""

import json

from botocore.exceptions import ClientError

from .base import AWSBaseCheck, Finding, Severity


class S3Checks(AWSBaseCheck):

    def run(self) -> list[Finding]:
        buckets = self._discover_artifact_buckets()
        if not buckets:
            return []

        s3 = self.session.client("s3")
        findings: list[Finding] = []
        for bucket in buckets:
            findings.extend(self._check_bucket(s3, bucket))
        return findings

    def _discover_artifact_buckets(self) -> set[str]:
        """Collect artifact bucket names from CodePipeline configurations.

        When self.target is set only that pipeline's artifact store is inspected;
        otherwise all pipelines in the region are enumerated.
        """
        buckets: set[str] = set()
        cp = self.session.client("codepipeline")

        def _extract_buckets(pipeline: dict) -> None:
            store = pipeline.get("artifactStore", {})
            if store.get("type") == "S3" and store.get("location"):
                buckets.add(store["location"])
            for store in pipeline.get("artifactStores", {}).values():
                if store.get("type") == "S3" and store.get("location"):
                    buckets.add(store["location"])

        try:
            if self.target:
                resp = cp.get_pipeline(name=self.target)
                _extract_buckets(resp["pipeline"])
            else:
                paginator = cp.get_paginator("list_pipelines")
                for page in paginator.paginate():
                    for summary in page.get("pipelines", []):
                        try:
                            resp = cp.get_pipeline(name=summary["name"])
                            _extract_buckets(resp["pipeline"])
                        except ClientError:
                            continue
        except ClientError:
            pass  # CodePipeline inaccessible — return empty

        return buckets

    def _check_bucket(self, s3, bucket: str) -> list[Finding]:
        return [
            self._s3001_public_access_block(s3, bucket),
            self._s3002_encryption(s3, bucket),
            self._s3003_versioning(s3, bucket),
            self._s3004_access_logging(s3, bucket),
            self._s3005_secure_transport(s3, bucket),
        ]

    @staticmethod
    def _s3005_secure_transport(s3, bucket: str) -> Finding:
        try:
            resp = s3.get_bucket_policy(Bucket=bucket)
            doc = json.loads(resp.get("Policy", "{}"))
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in ("NoSuchBucketPolicy", "NoSuchBucket"):
                return Finding(
                    check_id="S3-005",
                    title="Artifact bucket missing aws:SecureTransport deny",
                    severity=Severity.MEDIUM,
                    resource=bucket,
                    description=(
                        "No bucket policy is attached — plaintext HTTP requests "
                        "are not explicitly denied."
                    ),
                    recommendation=(
                        "Attach a bucket policy with a Deny for s3:* when "
                        "aws:SecureTransport is false."
                    ),
                    passed=False,
                )
            return Finding(
                check_id="S3-005",
                title="Artifact bucket missing aws:SecureTransport deny",
                severity=Severity.MEDIUM,
                resource=bucket,
                description=f"Could not retrieve bucket policy: {exc}",
                recommendation="Ensure s3:GetBucketPolicy permission.",
                passed=False,
            )
        except (ValueError, json.JSONDecodeError):
            doc = {}

        has_deny = False
        for stmt in doc.get("Statement", []):
            if stmt.get("Effect") != "Deny":
                continue
            cond = stmt.get("Condition", {}) or {}
            for operator_block in cond.values():
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
            "Bucket policy does not Deny requests where aws:SecureTransport is false."
        )
        return Finding(
            check_id="S3-005",
            title="Artifact bucket missing aws:SecureTransport deny",
            severity=Severity.MEDIUM,
            resource=bucket,
            description=desc,
            recommendation=(
                "Add a Deny statement for s3:* with Bool "
                "aws:SecureTransport=false."
            ),
            passed=has_deny,
        )

    @staticmethod
    def _s3001_public_access_block(s3, bucket: str) -> Finding:
        try:
            resp = s3.get_public_access_block(Bucket=bucket)
            cfg = resp.get("PublicAccessBlockConfiguration", {})
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
                return Finding(
                    check_id="S3-001",
                    title="Artifact bucket public access block not fully enabled",
                    severity=Severity.CRITICAL,
                    resource=bucket,
                    description=f"Could not retrieve public access block config: {exc}",
                    recommendation="Ensure s3:GetBucketPublicAccessBlock permission.",
                    passed=False,
                )

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

        return Finding(
            check_id="S3-001",
            title="Artifact bucket public access block not fully enabled",
            severity=Severity.CRITICAL,
            resource=bucket,
            description=desc,
            recommendation=(
                "Enable all four S3 Block Public Access settings on the artifact "
                "bucket: BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, "
                "and RestrictPublicBuckets."
            ),
            passed=fully_blocked,
        )

    @staticmethod
    def _s3002_encryption(s3, bucket: str) -> Finding:
        try:
            resp = s3.get_bucket_encryption(Bucket=bucket)
            rules = (
                resp.get("ServerSideEncryptionConfiguration", {})
                .get("Rules", [])
            )
            encrypted = len(rules) > 0
        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code", "")
            if error_code in ("ServerSideEncryptionConfigurationNotFoundError",
                              "NoSuchBucket"):
                encrypted = False
            else:
                return Finding(
                    check_id="S3-002",
                    title="Artifact bucket encryption not configured",
                    severity=Severity.HIGH,
                    resource=bucket,
                    description=f"Could not retrieve bucket encryption config: {exc}",
                    recommendation="Ensure s3:GetEncryptionConfiguration permission.",
                    passed=False,
                )

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

        return Finding(
            check_id="S3-002",
            title="Artifact bucket server-side encryption not configured",
            severity=Severity.HIGH,
            resource=bucket,
            description=desc,
            recommendation=(
                "Enable default bucket encryption using at minimum AES256 (SSE-S3). "
                "For stronger key control, use SSE-KMS with a customer-managed key."
            ),
            passed=encrypted,
        )

    @staticmethod
    def _s3003_versioning(s3, bucket: str) -> Finding:
        try:
            resp = s3.get_bucket_versioning(Bucket=bucket)
            status = resp.get("Status", "")
            passed = status == "Enabled"
        except ClientError as exc:
            return Finding(
                check_id="S3-003",
                title="Artifact bucket versioning not enabled",
                severity=Severity.MEDIUM,
                resource=bucket,
                description=f"Could not retrieve bucket versioning status: {exc}",
                recommendation="Ensure s3:GetBucketVersioning permission.",
                passed=False,
            )

        if passed:
            desc = "Versioning is enabled on the artifact bucket."
        else:
            desc = (
                "Versioning is not enabled on the artifact bucket. Without "
                "versioning, overwritten or deleted artifacts cannot be recovered, "
                "making it impossible to roll back to a known-good build artifact."
            )

        return Finding(
            check_id="S3-003",
            title="Artifact bucket versioning not enabled",
            severity=Severity.MEDIUM,
            resource=bucket,
            description=desc,
            recommendation=(
                "Enable S3 versioning on the artifact bucket so that previous "
                "artifact versions are retained and rollback is possible. Combine "
                "with a lifecycle rule to expire old versions after a retention period."
            ),
            passed=passed,
        )

    @staticmethod
    def _s3004_access_logging(s3, bucket: str) -> Finding:
        try:
            resp = s3.get_bucket_logging(Bucket=bucket)
            logging_enabled = "LoggingEnabled" in resp
        except ClientError as exc:
            return Finding(
                check_id="S3-004",
                title="Artifact bucket access logging not enabled",
                severity=Severity.LOW,
                resource=bucket,
                description=f"Could not retrieve bucket logging config: {exc}",
                recommendation="Ensure s3:GetBucketLogging permission.",
                passed=False,
            )

        if logging_enabled:
            target = resp["LoggingEnabled"].get("TargetBucket", "unknown")
            desc = f"Access logging is enabled; logs are delivered to '{target}'."
        else:
            desc = (
                "Server access logging is not enabled on the artifact bucket. "
                "Without access logs, it is not possible to audit who accessed, "
                "downloaded, or tampered with pipeline artifacts."
            )

        return Finding(
            check_id="S3-004",
            title="Artifact bucket access logging not enabled",
            severity=Severity.LOW,
            resource=bucket,
            description=desc,
            recommendation=(
                "Enable S3 server access logging for the artifact bucket and "
                "direct logs to a separate, centralised logging bucket with "
                "restricted write access."
            ),
            passed=logging_enabled,
        )
