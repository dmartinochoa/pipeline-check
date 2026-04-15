"""AWS provider — builds a boto3 Session and declares all AWS check classes.

To add a new AWS check module
------------------------------
1. Create ``pipeline_check/core/checks/aws/<service>.py`` subclassing AWSBaseCheck.
2. Import it here and add it to the list returned by ``check_classes``.
3. Add a rule YAML at ``pipeline_check/core/checks/aws/rules/<service>.yml``
   (optional, enriches the HTML report).
4. Add tests in ``tests/aws/test_<service>.py``.

Only this file needs to change — Scanner and CLI update automatically.
"""
from __future__ import annotations

from typing import Any

import boto3

from .base import BaseProvider
from ..checks.aws.codebuild import CodeBuildChecks
from ..checks.aws.codedeploy import CodeDeployChecks
from ..checks.aws.codepipeline import CodePipelineChecks
from ..checks.aws.ecr import ECRChecks
from ..checks.aws.iam import IAMChecks
from ..checks.aws.s3 import S3Checks
from ..checks.base import BaseCheck


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
        return [
            CodeBuildChecks,
            CodePipelineChecks,
            CodeDeployChecks,
            ECRChecks,
            IAMChecks,
            S3Checks,
        ]
