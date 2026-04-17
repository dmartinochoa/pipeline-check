"""AWS provider — builds a boto3 Session and wires the rule orchestrator.

To add a new AWS check
----------------------
1. Create ``pipeline_check/core/checks/aws/rules/<id_lower>_<slug>.py``
   exporting ``RULE`` (:class:`Rule` metadata) and
   ``check(catalog: ResourceCatalog) -> list[Finding]``.
   Use an existing rule such as ``cb008_inline_buildspec.py`` as a template.
2. If the rule needs a new AWS service, add a memoized enumeration method
   to :class:`ResourceCatalog` in ``aws/_catalog.py`` and register the
   rule's ID-prefix in ``aws/workflows.py``'s ``_RULE_PREFIX_TO_SERVICE``
   and ``_DEGRADED`` maps.
3. Add tests in ``tests/aws/test_<service>.py`` using the
   ``make_catalog`` fixture from ``tests/aws/rules/conftest.py``.

Every rule module is auto-discovered by :class:`AWSRuleChecks` via
``discover_rules("pipeline_check.core.checks.aws.rules")`` — this file,
Scanner, CLI, and the doc generator all update automatically.
"""
from __future__ import annotations

from typing import Any

import boto3

from ..checks.aws._catalog import ResourceCatalog
from ..checks.aws.workflows import AWSRuleChecks
from ..checks.base import BaseCheck
from ..inventory import Component
from .base import BaseProvider


class AWSProvider(BaseProvider):
    """Amazon Web Services CI/CD provider."""

    NAME = "aws"

    def build_context(
        self,
        region: str = "us-east-1",
        profile: str | None = None,
        **_: Any,
    ) -> boto3.Session:
        """Return a boto3 Session scoped to *region* and optional named *profile*."""
        return boto3.Session(region_name=region, profile_name=profile)

    @property
    def check_classes(self) -> list[type[BaseCheck]]:
        # Every AWS check is a rule module under aws/rules/, auto-discovered
        # by AWSRuleChecks via discover_rules(). Adding a new AWS check is a
        # single-file change: drop aws/rules/<id_lower>_<slug>.py.
        return [AWSRuleChecks]

    def inventory(self, context: boto3.Session) -> list[Component]:
        """Enumerate the CI/CD-relevant resources visible to *context*.

        Runs a ``ResourceCatalog`` pass over the services rules consume,
        plus a handful of additional enumerations (CloudBuild log groups,
        EventBridge rules, SSM parameters, IAM users, S3 artifact buckets)
        that are useful in an asset register but not load-bearing for any
        existing rule.

        Every enumeration is wrapped so a permission gap on one service
        produces a ``<service>_degraded`` marker rather than aborting
        the whole inventory.
        """
        from botocore.exceptions import ClientError

        catalog = ResourceCatalog(context)
        out: list[Component] = []

        def _emit(svc_type: str, identifier: str, source: str = "",
                  metadata: dict | None = None) -> None:
            out.append(Component(
                provider=self.NAME,
                type=svc_type,
                identifier=identifier,
                source=source or identifier,
                metadata={k: v for k, v in (metadata or {}).items() if v is not None},
            ))

        # ── Services already covered by the rule catalog ─────────────
        for proj in catalog.codebuild_projects():
            env = proj.get("environment") or {}
            _emit(
                "codebuild_project",
                proj.get("name", "<unnamed>"),
                source=proj.get("arn", ""),
                metadata={
                    "image": env.get("image"),
                    "compute_type": env.get("computeType"),
                    "privileged_mode": bool(env.get("privilegedMode")),
                    "timeout_minutes": proj.get("timeoutInMinutes"),
                    "source_type": (proj.get("source") or {}).get("type"),
                    "service_role": proj.get("serviceRole"),
                },
            )
        for pipe in catalog.codepipeline_pipelines():
            _emit(
                "codepipeline",
                pipe.get("name", "<unnamed>"),
                metadata={
                    "pipeline_type": pipe.get("pipelineType"),
                    "stage_count": len(pipe.get("stages") or []),
                    "role_arn": pipe.get("roleArn"),
                },
            )
        for role in catalog.cicd_roles():
            _emit(
                "iam_role",
                role.get("RoleName", "<unnamed>"),
                source=role.get("Arn", ""),
                metadata={
                    "permissions_boundary": bool(role.get("PermissionsBoundary")),
                    "create_date": str(role.get("CreateDate")) if role.get("CreateDate") else None,
                },
            )
        for trail in catalog.cloudtrail_trails():
            _emit(
                "cloudtrail_trail",
                trail.get("Name", "<unnamed>"),
                source=trail.get("TrailARN", ""),
                metadata={
                    "multi_region": bool(trail.get("IsMultiRegionTrail")),
                    "log_file_validation": bool(trail.get("LogFileValidationEnabled")),
                    "is_logging": bool(trail.get("_IsLogging")),
                },
            )
        for secret in catalog.secrets():
            _emit(
                "secretsmanager_secret",
                secret.get("Name", "<unnamed>"),
                source=secret.get("ARN", ""),
                metadata={
                    "rotation_enabled": bool(secret.get("RotationEnabled")),
                    "last_rotated": str(secret.get("LastRotatedDate")) if secret.get("LastRotatedDate") else None,
                },
            )
        for domain in catalog.codeartifact_domains():
            _emit(
                "codeartifact_domain",
                domain.get("name", "<unnamed>"),
                source=domain.get("arn", ""),
                metadata={"encryption_key": domain.get("encryptionKey")},
            )
        for repo in catalog.codeartifact_repositories():
            _emit(
                "codeartifact_repository",
                repo.get("name", "<unnamed>"),
                source=repo.get("arn", ""),
                metadata={"domain": repo.get("domainName")},
            )
        for repo in catalog.codecommit_repositories():
            _emit(
                "codecommit_repository",
                repo.get("repositoryName", "<unnamed>"),
                source=repo.get("repositoryId", ""),
            )
        for fn in catalog.lambda_functions():
            _emit(
                "lambda_function",
                fn.get("FunctionName", "<unnamed>"),
                source=fn.get("FunctionArn", ""),
                metadata={
                    "runtime": fn.get("Runtime"),
                    "handler": fn.get("Handler"),
                    "memory_mb": fn.get("MemorySize"),
                    "timeout_seconds": fn.get("Timeout"),
                    "code_signing_config_arn": fn.get("CodeSigningConfigArn"),
                    "architectures": fn.get("Architectures"),
                },
            )
        for key in catalog.kms_keys():
            _emit(
                "kms_key",
                key.get("KeyId", "<unnamed>"),
                source=key.get("Arn", ""),
                metadata={
                    "key_spec": key.get("KeySpec"),
                    "key_usage": key.get("KeyUsage"),
                    "key_state": key.get("KeyState"),
                },
            )

        # ── Additional resource types (inventory-only; no rule uses them) ──
        for lg in catalog.log_groups("/aws/codebuild/"):
            _emit(
                "cloudwatch_log_group",
                lg.get("logGroupName", "<unnamed>"),
                source=lg.get("arn", ""),
                metadata={
                    "retention_days": lg.get("retentionInDays"),
                    "kms_key_id": lg.get("kmsKeyId"),
                    "stored_bytes": lg.get("storedBytes"),
                },
            )
        for param in catalog.ssm_parameters():
            _emit(
                "ssm_parameter",
                param.get("Name", "<unnamed>"),
                source=param.get("ARN", ""),
                metadata={
                    "parameter_type": param.get("Type"),
                    "tier": param.get("Tier"),
                    "key_id": param.get("KeyId"),
                },
            )
        for rule in catalog.eventbridge_rules():
            _emit(
                "eventbridge_rule",
                rule.get("Name", "<unnamed>"),
                source=rule.get("Arn", ""),
                metadata={
                    "state": rule.get("State"),
                    "schedule": rule.get("ScheduleExpression"),
                },
            )
        for ptc in catalog.ecr_pull_through_cache_rules():
            _emit(
                "ecr_pull_through_cache_rule",
                ptc.get("ecrRepositoryPrefix", "<unnamed>"),
                metadata={
                    "upstream": ptc.get("upstreamRegistryUrl"),
                    "has_credential": bool(ptc.get("credentialArn")),
                },
            )

        # ECR repositories — now catalog-backed; reuses the same
        # memoized enumeration that ECR-001..005 rules consume.
        for repo in catalog.ecr_repositories():
            enc = repo.get("encryptionConfiguration") or {}
            scan = repo.get("imageScanningConfiguration") or {}
            _emit(
                "ecr_repository",
                repo.get("repositoryName", "<unnamed>"),
                source=repo.get("repositoryArn", ""),
                metadata={
                    "tag_mutability": repo.get("imageTagMutability"),
                    "encryption_type": enc.get("encryptionType"),
                    "scan_on_push": bool(scan.get("scanOnPush")),
                },
            )

        # S3 artifact buckets — discovered via CodePipeline, then
        # dereferenced for their per-bucket config. Per-bucket API calls
        # aren't worth hoisting into the catalog (no rule shares them).
        artifact_buckets = catalog.s3_artifact_buckets()
        s3 = context.client("s3") if artifact_buckets else None
        for bucket in artifact_buckets:
            meta: dict = {"bucket_name": bucket}
            try:
                ver = s3.get_bucket_versioning(Bucket=bucket)
                meta["versioning"] = ver.get("Status")
            except ClientError:
                pass
            try:
                pab = s3.get_public_access_block(Bucket=bucket)
                cfg = pab.get("PublicAccessBlockConfiguration") or {}
                meta["public_access_blocked"] = all(
                    bool(cfg.get(k)) for k in (
                        "BlockPublicAcls", "IgnorePublicAcls",
                        "BlockPublicPolicy", "RestrictPublicBuckets",
                    )
                )
            except ClientError:
                meta["public_access_blocked"] = False
            _emit(
                "s3_bucket",
                bucket,
                source=f"arn:aws:s3:::{bucket}",
                metadata=meta,
            )

        # IAM users — separate from cicd_roles; useful for access-key
        # age dashboards and human-inventory audits. Use the catalog
        # method so failures route through ``catalog.errors``.
        for user in catalog.iam_users():
            active_keys = 0
            for k in catalog.access_keys(user.get("UserName", "")):
                if k.get("Status") == "Active":
                    active_keys += 1
            _emit(
                "iam_user",
                user.get("UserName", "<unnamed>"),
                source=user.get("Arn", ""),
                metadata={
                    "active_access_keys": active_keys,
                    "create_date": str(user.get("CreateDate")) if user.get("CreateDate") else None,
                },
            )

        # Surface any degraded services so the inventory isn't silently
        # incomplete — the operator can see "we couldn't enumerate X".
        for svc, err in catalog.errors.items():
            _emit(f"{svc}_degraded", svc, metadata={"error": err})
        return out
