"""Terraform provider.

Two input paths, same rule pack:

Plan JSON (canonical, fully resolved attributes):

    terraform plan -out=tfplan
    terraform show -json tfplan > plan.json
    pipeline_check --pipeline terraform --tf-plan plan.json

HCL source (best-effort, no ``terraform`` binary required):

    pipeline_check --pipeline terraform --tf-source ./infra/

The plan path stays canonical: every attribute is already resolved and
typed. The HCL path is best-effort, variable/local substitution is
partial, and unresolvable references stay opaque. Both paths produce the
same ``TerraformContext`` so the 58-rule pack runs unchanged.
"""
from __future__ import annotations

from typing import Any

from ..checks.base import BaseCheck
from ..checks.terraform.base import TerraformContext
from ..checks.terraform.workflows import TerraformRuleChecks
from ..inventory import Component
from .base import BaseProvider


# Metadata extraction per Terraform resource type. Only fields that are
# security- or audit-relevant are surfaced, full attribute dumps would
# bloat the inventory and leak the same details the findings already
# cover. Every field is optional; missing values are simply omitted.
def _tf_metadata(resource_type: str, values: dict[str, Any]) -> dict[str, Any]:
    meta: dict[str, Any] = {}
    # Tags are common across aws_*, pick them up everywhere.
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
    """Scans Terraform via plan JSON or direct HCL source."""

    NAME = "terraform"

    def build_context(
        self,
        tf_plan: str | None = None,
        tf_source: str | None = None,
        **_: Any,
    ) -> TerraformContext:
        if tf_plan:
            return TerraformContext.from_path(tf_plan)
        if tf_source:
            return TerraformContext.from_hcl_dir(tf_source)
        raise ValueError(
            "The terraform provider requires either "
            "--tf-plan <path> (JSON output of `terraform show -json`) "
            "or --tf-source <directory> (directory containing *.tf files, "
            "requires `pip install pipeline-check[hcl]`)."
        )

    @property
    def check_classes(self) -> list[type[BaseCheck[Any]]]:
        # Single orchestrator that auto-discovers every rule under
        # ``pipeline_check.core.checks.terraform.rules``. The legacy
        # per-service check classes (CodeBuildChecks, IAMChecks, …)
        # still exist for the per-service unit tests under
        # ``tests/terraform/`` but no longer participate in scans —
        # they delegate to the same helper functions the rule modules
        # call, so both paths share their semantics.
        return [TerraformRuleChecks]

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
