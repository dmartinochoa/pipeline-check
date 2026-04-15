"""Terraform CodeBuild checks (CB-001 … CB-005).

Check IDs and semantics mirror the AWS-provider versions exactly — the
only difference is the data source (``terraform show -json`` vs. boto3).
"""
from __future__ import annotations

import re

from .base import TerraformBaseCheck
from ..base import Finding, Severity

_SECRET_NAME_RE = re.compile(
    r"(PASSWORD|PASSWD|PWD|SECRET|TOKEN|API[_\-]?KEY|ACCESS[_\-]?KEY|"
    r"SECRET[_\-]?KEY|PRIVATE[_\-]?KEY|CREDENTIAL|AUTH|AUTHORIZATION)",
    re.IGNORECASE,
)
_MANAGED_IMAGE_RE = re.compile(r"aws/codebuild/standard:(\d+)\.\d+")
_LATEST_STANDARD_VERSION = 7
_MAX_SENSIBLE_TIMEOUT = 480


def _first(block_list: list | None) -> dict:
    """Terraform represents single-nested blocks as 1-item lists."""
    if not block_list:
        return {}
    return block_list[0] or {}


class CodeBuildChecks(TerraformBaseCheck):
    """Runs CB-XXX checks over every aws_codebuild_project in the plan."""

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for r in self.ctx.resources("aws_codebuild_project"):
            findings.extend([
                _cb001_plaintext_secrets(r.values, r.address),
                _cb002_privileged_mode(r.values, r.address),
                _cb003_logging_enabled(r.values, r.address),
                _cb004_timeout(r.values, r.address),
                _cb005_image_version(r.values, r.address),
            ])
        return findings


def _cb001_plaintext_secrets(values: dict, address: str) -> Finding:
    suspicious: list[str] = []
    for env_block in values.get("environment", []) or []:
        for env_var in env_block.get("environment_variable", []) or []:
            name = env_var.get("name", "")
            var_type = env_var.get("type") or "PLAINTEXT"
            if var_type == "PLAINTEXT" and _SECRET_NAME_RE.search(name):
                suspicious.append(name)

    passed = not suspicious
    desc = (
        "No plaintext environment variables with secret-like names detected."
        if passed else
        f"The following environment variables appear to store secrets in "
        f"plaintext: {', '.join(suspicious)}. Plaintext values are visible in "
        f"the AWS console, CloudTrail logs, and build logs."
    )
    return Finding(
        check_id="CB-001",
        title="Secrets in plaintext environment variables",
        severity=Severity.CRITICAL,
        resource=address,
        description=desc,
        recommendation=(
            "Move secrets to AWS Secrets Manager or SSM Parameter Store and "
            "reference them using type SECRETS_MANAGER or PARAMETER_STORE in "
            "the CodeBuild environment_variable block."
        ),
        passed=passed,
    )


def _cb002_privileged_mode(values: dict, address: str) -> Finding:
    env = _first(values.get("environment"))
    privileged = bool(env.get("privileged_mode", False))
    desc = (
        "Privileged mode is not enabled on this project."
        if not privileged else
        "Privileged mode is enabled. This grants the build container root-level "
        "access to the Docker daemon on the host, which is only necessary for "
        "Docker-in-Docker builds."
    )
    return Finding(
        check_id="CB-002",
        title="Privileged mode enabled",
        severity=Severity.HIGH,
        resource=address,
        description=desc,
        recommendation=(
            "Disable privileged mode unless the project explicitly requires "
            "Docker-in-Docker builds."
        ),
        passed=not privileged,
    )


def _cb003_logging_enabled(values: dict, address: str) -> Finding:
    logs = _first(values.get("logs_config"))
    cw = _first(logs.get("cloudwatch_logs"))
    s3 = _first(logs.get("s3_logs"))
    # In Terraform the default status is ENABLED for cloudwatch_logs when the
    # logs_config block is absent. When the block exists, respect what's set.
    if not logs:
        cw_enabled = True
        s3_enabled = False
    else:
        cw_enabled = (cw.get("status") or "ENABLED") == "ENABLED"
        s3_enabled = (s3.get("status") or "DISABLED") == "ENABLED"
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
            "Neither CloudWatch Logs nor S3 logging is enabled for this project. "
            "Without logs, build activity cannot be audited."
        )

    return Finding(
        check_id="CB-003",
        title="Build logging not enabled",
        severity=Severity.MEDIUM,
        resource=address,
        description=desc,
        recommendation=(
            "Enable CloudWatch Logs or S3 logging in logs_config."
        ),
        passed=passed,
    )


def _cb004_timeout(values: dict, address: str) -> Finding:
    timeout = values.get("build_timeout")
    passed = timeout is not None and timeout < _MAX_SENSIBLE_TIMEOUT
    desc = (
        f"Build timeout is set to {timeout} minutes."
        if passed else
        f"Build timeout is {timeout or 'default'} minutes (AWS maximum). Runaway or "
        f"abused builds can drive up costs and delay detection of a compromised pipeline."
    )
    return Finding(
        check_id="CB-004",
        title="No build timeout configured",
        severity=Severity.LOW,
        resource=address,
        description=desc,
        recommendation=(
            "Set a build timeout appropriate for your expected build duration "
            "(typically 15–60 minutes)."
        ),
        passed=passed,
    )


def _cb005_image_version(values: dict, address: str) -> Finding:
    env = _first(values.get("environment"))
    image = env.get("image", "") or ""
    match = _MANAGED_IMAGE_RE.search(image)
    if match:
        version = int(match.group(1))
        passed = version >= _LATEST_STANDARD_VERSION
        desc = (
            f"Project uses the current managed image (aws/codebuild/standard:{version}.0)."
            if passed else
            f"Project uses aws/codebuild/standard:{version}.0, which is outdated "
            f"(latest: {_LATEST_STANDARD_VERSION}.0)."
        )
    else:
        passed = True
        desc = (
            f"Project uses a non-standard image ({image!r}); automated version check "
            f"skipped."
        )
    return Finding(
        check_id="CB-005",
        title="Outdated managed build image",
        severity=Severity.MEDIUM,
        resource=address,
        description=desc,
        recommendation=(
            f"Update the CodeBuild environment image to "
            f"aws/codebuild/standard:{_LATEST_STANDARD_VERSION}.0 or later."
        ),
        passed=passed,
    )
