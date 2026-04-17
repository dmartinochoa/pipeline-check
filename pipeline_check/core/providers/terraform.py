"""Terraform provider — scans a ``terraform show -json`` plan document.

The provider consumes the post-plan JSON output rather than parsing raw HCL,
so every attribute is already resolved and typed. Producer workflow:

    terraform plan -out=tfplan
    terraform show -json tfplan > plan.json
    pipeline_check --pipeline terraform --tf-plan plan.json

To add a new Terraform check module
------------------------------------
1. Create ``pipeline_check/core/checks/terraform/<service>.py`` subclassing
   ``TerraformBaseCheck``.
2. Import it here and append it to the ``check_classes`` property.
3. Add unit tests under ``tests/terraform/``.
"""
from __future__ import annotations

from typing import Any

from ..checks.base import BaseCheck
from ..checks.terraform.base import TerraformContext
from ..checks.terraform.codebuild import CodeBuildChecks
from ..checks.terraform.codedeploy import CodeDeployChecks
from ..checks.terraform.codepipeline import CodePipelineChecks
from ..checks.terraform.ecr import ECRChecks
from ..checks.terraform.extended import ExtendedChecks
from ..checks.terraform.iam import IAMChecks
from ..checks.terraform.pbac import PBACChecks
from ..checks.terraform.phase3 import Phase3Checks
from ..checks.terraform.s3 import S3Checks
from ..checks.terraform.services import ServiceChecks
from ..inventory import Component
from .base import BaseProvider


# Metadata extraction per Terraform resource type. Only fields that are
# security- or audit-relevant are surfaced — full attribute dumps would
# bloat the inventory and leak the same details the findings already
# cover. Every field is optional; missing values are simply omitted.
def _tf_metadata(resource_type: str, values: dict) -> dict:
    meta: dict = {}
    # Tags are common across aws_* — pick them up everywhere.
    tags = values.get("tags")
    if isinstance(tags, dict) and tags:
        meta["tags"] = tags
    # ARN is the canonical identifier for AWS resources; Terraform
    # populates it post-apply but includes it in most plan JSON.
    arn = values.get("arn")
    if isinstance(arn, str) and arn:
        meta["arn"] = arn

    if resource_type == "aws_codebuild_project":
        env = (values.get("environment") or [{}])[0] or {}
        meta["image"] = env.get("image")
        meta["compute_type"] = env.get("compute_type")
        meta["privileged_mode"] = bool(env.get("privileged_mode"))
        if src_list := values.get("source"):
            meta["source_type"] = (src_list[0] or {}).get("type")
        meta["timeout_minutes"] = values.get("build_timeout")
    elif resource_type == "aws_codepipeline":
        meta["stage_count"] = len(values.get("stage") or [])
        meta["pipeline_type"] = values.get("pipeline_type")
    elif resource_type == "aws_iam_role":
        meta["permissions_boundary"] = bool(values.get("permissions_boundary"))
        meta["managed_policy_count"] = len(values.get("managed_policy_arns") or [])
    elif resource_type == "aws_s3_bucket":
        meta["bucket_name"] = values.get("bucket")
    elif resource_type == "aws_ecr_repository":
        meta["tag_mutability"] = values.get("image_tag_mutability")
        scan_cfg = (values.get("image_scanning_configuration") or [{}])[0] or {}
        meta["scan_on_push"] = bool(scan_cfg.get("scan_on_push"))
    elif resource_type == "aws_lambda_function":
        meta["runtime"] = values.get("runtime")
        meta["handler"] = values.get("handler")
        meta["code_signing_config_arn"] = values.get("code_signing_config_arn")
    elif resource_type == "aws_kms_key":
        meta["key_rotation"] = bool(values.get("enable_key_rotation"))
        meta["key_spec"] = values.get("customer_master_key_spec") or "SYMMETRIC_DEFAULT"
    elif resource_type == "aws_cloudtrail":
        meta["multi_region"] = bool(values.get("is_multi_region_trail"))
        meta["log_file_validation"] = bool(values.get("enable_log_file_validation"))
    elif resource_type == "aws_secretsmanager_secret":
        meta["secret_name"] = values.get("name")
    elif resource_type == "aws_ssm_parameter":
        meta["parameter_type"] = values.get("type")
    # Prune Nones so downstream consumers don't have to branch.
    return {k: v for k, v in meta.items() if v is not None}


class TerraformProvider(BaseProvider):
    """Scans a parsed ``terraform show -json`` document."""

    NAME = "terraform"

    def build_context(self, tf_plan: str | None = None, **_: Any) -> TerraformContext:
        if not tf_plan:
            raise ValueError(
                "The terraform provider requires --tf-plan <path> pointing at "
                "the JSON output of `terraform show -json`."
            )
        return TerraformContext.from_path(tf_plan)

    @property
    def check_classes(self) -> list[type[BaseCheck]]:
        return [
            CodeBuildChecks,
            CodePipelineChecks,
            CodeDeployChecks,
            ECRChecks,
            IAMChecks,
            PBACChecks,
            S3Checks,
            ExtendedChecks,
            ServiceChecks,
            Phase3Checks,
        ]

    def inventory(self, context: TerraformContext) -> list[Component]:
        out: list[Component] = []
        for r in context.resources():
            out.append(Component(
                provider=self.NAME,
                type=r.type,
                identifier=r.name,
                source=r.address,
                metadata=_tf_metadata(r.type, r.values),
            ))
        return out
