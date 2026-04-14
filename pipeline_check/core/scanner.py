"""Scanner — orchestrates all check modules.

Adding a new check module:
    1. Create pipeline_check/core/checks/<service>.py with a class that
       subclasses BaseCheck, sets PROVIDER, and implements run() -> list[Finding].
    2. Import it here and add it to _CHECK_CLASSES.

Adding support for a new provider (e.g. gcp, github, azure):
    1. Create check modules with PROVIDER = "<provider>".
    2. Add a branch in Scanner.__init__ to build the appropriate context for
       that provider and pass it when instantiating check classes.
"""

from __future__ import annotations

from typing import Any, Optional

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
    # Future: GCPCloudBuildChecks, GitHubActionsChecks, AzurePipelinesChecks
]


class Scanner:
    """Runs registered check modules for a given pipeline provider."""

    def __init__(
        self,
        pipeline: str = "aws",
        region: str = "us-east-1",
        profile: Optional[str] = None,
    ) -> None:
        self.pipeline = pipeline.lower()

        # Build the provider context passed to every check class.
        # Add new branches here as providers are implemented.
        if self.pipeline == "aws":
            self._context: Any = boto3.Session(
                region_name=region,
                profile_name=profile,
            )
        elif self.pipeline == "gcp":
            # Placeholder: future GCP checks will receive a google-auth
            # credentials object or a google.cloud client here.
            self._context = None
        elif self.pipeline == "github":
            # Placeholder: future GitHub checks will receive a PyGithub
            # client or a raw token here.
            self._context = None
        elif self.pipeline == "azure":
            # Placeholder: future Azure checks will receive an azure-identity
            # credential object here.
            self._context = None
        else:
            self._context = None

    def run(self, checks: Optional[list[str]] = None) -> list[Finding]:
        """Execute every registered check module for the active provider.

        Parameters
        ----------
        checks:
            Optional allowlist of check IDs (e.g. ``["CB-001", "CB-003"]``).
            When provided, only findings whose ``check_id`` matches are kept.
        """
        provider_classes = [
            cls for cls in _CHECK_CLASSES if cls.PROVIDER == self.pipeline
        ]

        findings: list[Finding] = []
        for check_class in provider_classes:
            checker = check_class(self._context)
            findings.extend(checker.run())

        if checks:
            normalised = {c.upper() for c in checks}
            findings = [f for f in findings if f.check_id.upper() in normalised]

        return findings