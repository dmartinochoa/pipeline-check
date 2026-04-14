"""Scanner -- orchestrates all check modules.

Adding a new check module:
    1. Create pipelineguard/core/checks/<service>.py with a class that
       subclasses BaseCheck and implements run() -> list[Finding].
    2. Import it here and add it to _CHECK_CLASSES.
"""

from __future__ import annotations

from typing import Optional

import boto3

from .checks.base import Finding
from .checks.codebuild import CodeBuildChecks
from .checks.codedeploy import CodeDeployChecks
from .checks.codepipeline import CodePipelineChecks
from .checks.ecr import ECRChecks
from .checks.iam import IAMChecks
from .checks.s3 import S3Checks

_CHECK_CLASSES = [
    CodeBuildChecks,
    CodePipelineChecks,
    CodeDeployChecks,
    ECRChecks,
    IAMChecks,
    S3Checks,
]


class Scanner:
    """Runs all registered check modules and aggregates their findings."""

    def __init__(
        self,
        region: str = "us-east-1",
        profile: Optional[str] = None,
    ) -> None:
        self.session = boto3.Session(
            region_name=region,
            profile_name=profile,
        )

    def run(self) -> list[Finding]:
        """Execute every registered check module and return all findings."""
        findings: list[Finding] = []
        for check_class in _CHECK_CLASSES:
            checker = check_class(self.session)
            findings.extend(checker.run())
        return findings
