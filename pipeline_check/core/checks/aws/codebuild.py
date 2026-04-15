"""CodeBuild security checks.

CB-001  Secrets in plaintext environment variables      CRITICAL  CICD-SEC-6
CB-002  Privileged mode enabled                         HIGH      CICD-SEC-7
CB-003  Build logging not enabled                       MEDIUM    CICD-SEC-10
CB-004  No build timeout configured                     LOW       CICD-SEC-7
CB-005  Outdated managed build image                    MEDIUM    CICD-SEC-7
"""

import re

from botocore.exceptions import ClientError

from .base import AWSBaseCheck, Finding, Severity

# Environment variable names that suggest a secret is stored in plaintext.
_SECRET_NAME_RE = re.compile(
    r"(PASSWORD|PASSWD|PWD|SECRET|TOKEN|API[_\-]?KEY|ACCESS[_\-]?KEY|"
    r"SECRET[_\-]?KEY|PRIVATE[_\-]?KEY|CREDENTIAL|AUTH|AUTHORIZATION)",
    re.IGNORECASE,
)

# AWS CodeBuild standard managed-image pattern: aws/codebuild/standard:X.0
_MANAGED_IMAGE_RE = re.compile(r"aws/codebuild/standard:(\d+)\.\d+")

# Bump this when AWS releases a new standard image version.
_LATEST_STANDARD_VERSION = 7

# Projects with a timeout at or above this are considered unconstrained.
_MAX_SENSIBLE_TIMEOUT = 480  # minutes (AWS maximum)


class CodeBuildChecks(AWSBaseCheck):
    """Runs all CB-XXX checks across every CodeBuild project in the region."""

    def run(self) -> list[Finding]:
        client = self.session.client("codebuild")

        try:
            project_names = self._list_projects(client)
        except ClientError as exc:
            return [Finding(
                check_id="CB-000",
                title="CodeBuild API access failed",
                severity=Severity.INFO,
                resource="codebuild",
                description=(
                    f"Could not list CodeBuild projects: {exc}. "
                    "Remaining CB checks were skipped."
                ),
                recommendation=(
                    "Ensure the IAM principal has codebuild:ListProjects and "
                    "codebuild:BatchGetProjects permissions."
                ),
                passed=False,
            )]

        if not project_names:
            return []

        findings: list[Finding] = []
        # BatchGetProjects accepts up to 100 names per call.
        for i in range(0, len(project_names), 100):
            batch = project_names[i : i + 100]
            try:
                response = client.batch_get_projects(names=batch)
            except ClientError:
                continue
            for project in response.get("projects", []):
                findings.extend(self._check_project(project))

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _list_projects(client) -> list[str]:
        names: list[str] = []
        paginator = client.get_paginator("list_projects")
        for page in paginator.paginate():
            names.extend(page.get("projects", []))
        return names

    def _check_project(self, project: dict) -> list[Finding]:
        name: str = project["name"]
        return [
            self._cb001_plaintext_secrets(project, name),
            self._cb002_privileged_mode(project, name),
            self._cb003_logging_enabled(project, name),
            self._cb004_timeout(project, name),
            self._cb005_image_version(project, name),
        ]

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    @staticmethod
    def _cb001_plaintext_secrets(project: dict, name: str) -> Finding:
        env_vars: list[dict] = project.get("environment", {}).get(
            "environmentVariables", []
        )
        suspicious = [
            v["name"]
            for v in env_vars
            if v.get("type", "PLAINTEXT") == "PLAINTEXT"
            and _SECRET_NAME_RE.search(v["name"])
        ]
        passed = not suspicious

        if passed:
            desc = "No plaintext environment variables with secret-like names detected."
        else:
            listed = ", ".join(suspicious)
            desc = (
                f"The following environment variables appear to store secrets in "
                f"plaintext: {listed}. Plaintext values are visible in the AWS "
                f"console, CloudTrail logs, and build logs."
            )

        return Finding(
            check_id="CB-001",
            title="Secrets in plaintext environment variables",
            severity=Severity.CRITICAL,
            resource=name,
            description=desc,
            recommendation=(
                "Move secrets to AWS Secrets Manager or SSM Parameter Store and "
                "reference them using type SECRETS_MANAGER or PARAMETER_STORE in "
                "the CodeBuild environment variable configuration."
            ),
            passed=passed,
        )

    @staticmethod
    def _cb002_privileged_mode(project: dict, name: str) -> Finding:
        privileged: bool = project.get("environment", {}).get("privilegedMode", False)

        if not privileged:
            desc = "Privileged mode is not enabled on this project."
        else:
            desc = (
                "Privileged mode is enabled. This grants the build container "
                "root-level access to the Docker daemon on the host, which is only "
                "necessary for Docker-in-Docker builds. A compromised build could "
                "escape the container or tamper with the host."
            )

        return Finding(
            check_id="CB-002",
            title="Privileged mode enabled",
            severity=Severity.HIGH,
            resource=name,
            description=desc,
            recommendation=(
                "Disable privileged mode unless the project explicitly requires "
                "Docker-in-Docker builds. If required, ensure the buildspec is "
                "tightly controlled, peer-reviewed, and sourced from a trusted "
                "repository with branch protection."
            ),
            passed=not privileged,
        )

    @staticmethod
    def _cb003_logging_enabled(project: dict, name: str) -> Finding:
        logs = project.get("logsConfig", {})
        cw_enabled = logs.get("cloudWatchLogs", {}).get("status") == "ENABLED"
        s3_enabled = logs.get("s3Logs", {}).get("status") == "ENABLED"
        passed = cw_enabled or s3_enabled

        if passed:
            dest = []
            if cw_enabled:
                dest.append("CloudWatch Logs")
            if s3_enabled:
                dest.append("S3")
            desc = f"Build logging is enabled ({' and '.join(dest)})."
        else:
            desc = (
                "Neither CloudWatch Logs nor S3 logging is enabled for this "
                "project. Without logs, build activity cannot be audited and "
                "security incidents cannot be investigated or attributed."
            )

        return Finding(
            check_id="CB-003",
            title="Build logging not enabled",
            severity=Severity.MEDIUM,
            resource=name,
            description=desc,
            recommendation=(
                "Enable CloudWatch Logs or S3 logging in the CodeBuild project "
                "configuration to maintain a durable audit trail of all build "
                "activity."
            ),
            passed=passed,
        )

    @staticmethod
    def _cb004_timeout(project: dict, name: str) -> Finding:
        timeout: int | None = project.get("timeoutInMinutes")
        # Flag if timeout is at the AWS maximum (480 min), which suggests the
        # operator accepted the ceiling without setting a tighter bound.
        passed = timeout is not None and timeout < _MAX_SENSIBLE_TIMEOUT

        if passed:
            desc = f"Build timeout is set to {timeout} minutes."
        else:
            t_str = str(timeout) if timeout is not None else "default"
            desc = (
                f"Build timeout is {t_str} minutes (AWS maximum). Runaway or "
                f"abused builds can drive up costs and delay detection of a "
                f"compromised pipeline."
            )

        return Finding(
            check_id="CB-004",
            title="No build timeout configured",
            severity=Severity.LOW,
            resource=name,
            description=desc,
            recommendation=(
                "Set a build timeout appropriate for your expected build duration "
                "(typically 15–60 minutes) to limit the blast radius of a runaway "
                "or abused build."
            ),
            passed=passed,
        )

    @staticmethod
    def _cb005_image_version(project: dict, name: str) -> Finding:
        image: str = project.get("environment", {}).get("image", "")
        match = _MANAGED_IMAGE_RE.search(image)

        if match:
            version = int(match.group(1))
            passed = version >= _LATEST_STANDARD_VERSION
            if passed:
                desc = (
                    f"Project uses the current managed image "
                    f"(aws/codebuild/standard:{version}.0)."
                )
            else:
                desc = (
                    f"Project uses aws/codebuild/standard:{version}.0, which is "
                    f"outdated (latest: {_LATEST_STANDARD_VERSION}.0). Older images "
                    f"may contain unpatched OS packages, runtimes, or tools that "
                    f"introduce supply-chain risk."
                )
        else:
            # Custom or third-party image — version assessment is not applicable.
            passed = True
            desc = (
                f"Project uses a non-standard image ({image!r}); "
                f"automated version check skipped. Ensure this image is regularly "
                f"updated and sourced from a trusted registry."
            )

        return Finding(
            check_id="CB-005",
            title="Outdated managed build image",
            severity=Severity.MEDIUM,
            resource=name,
            description=desc,
            recommendation=(
                f"Update the CodeBuild environment image to "
                f"aws/codebuild/standard:{_LATEST_STANDARD_VERSION}.0 or later "
                f"to ensure the build environment receives the latest security patches."
            ),
            passed=passed,
        )
