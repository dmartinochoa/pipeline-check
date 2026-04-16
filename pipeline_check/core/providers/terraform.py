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
from ..checks.terraform.iam import IAMChecks
from ..checks.terraform.pbac import PBACChecks
from ..checks.terraform.s3 import S3Checks
from .base import BaseProvider


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
        ]
