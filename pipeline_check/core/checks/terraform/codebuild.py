"""Terraform CodeBuild checks.

CB-001  Secrets in plaintext environment variables          CRITICAL  CICD-SEC-6
CB-002  Privileged mode enabled                             HIGH      CICD-SEC-7
CB-003  Build logging not enabled                           MEDIUM    CICD-SEC-10
CB-004  No build timeout configured                         LOW       CICD-SEC-7
CB-005  Outdated managed build image                        MEDIUM    CICD-SEC-7
CB-006  Source auth uses long-lived token (not CodeConnect) HIGH      CICD-SEC-6
CB-007  CodeBuild webhook has no filter_group               MEDIUM    CICD-SEC-1

CB-001 fails on **either** a secret-like variable name (PASSWORD, TOKEN, …)
**or** a value that looks like a credential (AKIA…, ghp_…, xoxb-…, eyJ…).
"""
from __future__ import annotations

from .base import TerraformBaseCheck
from ..base import Finding, Severity
from .._patterns import (
    LATEST_STANDARD_VERSION as _LATEST_STANDARD_VERSION,
    MANAGED_IMAGE_RE as _MANAGED_IMAGE_RE,
    SECRET_NAME_RE as _SECRET_NAME_RE,
    SECRET_VALUE_RE as _SECRET_VALUE_RE,
)

_MAX_SENSIBLE_TIMEOUT = 480


def _first(block_list: list | None) -> dict:
    if not block_list:
        return {}
    return block_list[0] or {}


class CodeBuildChecks(TerraformBaseCheck):

    def run(self) -> list[Finding]:
        # CB-006 and CB-007 need side resources.
        source_creds: dict[str, str] = {}
        for r in self.ctx.resources("aws_codebuild_source_credential"):
            server = r.values.get("server_type", "")
            auth = r.values.get("auth_type", "")
            if server and auth:
                source_creds[server] = auth

        webhooks: dict[str, dict] = {}
        for r in self.ctx.resources("aws_codebuild_webhook"):
            proj = r.values.get("project_name", "")
            if proj:
                webhooks[proj] = r.values

        findings: list[Finding] = []
        for r in self.ctx.resources("aws_codebuild_project"):
            name = r.values.get("name") or r.name
            findings.extend([
                _cb001_plaintext_secrets(r.values, r.address),
                _cb002_privileged_mode(r.values, r.address),
                _cb003_logging_enabled(r.values, r.address),
                _cb004_timeout(r.values, r.address),
                _cb005_image_version(r.values, r.address),
                _cb006_source_auth(r.values, source_creds, r.address),
                _cb007_webhook_filter(webhooks.get(name), r.address),
            ])
        return findings


def _cb001_plaintext_secrets(values: dict, address: str) -> Finding:
    suspicious_names: list[str] = []
    suspicious_values: list[str] = []
    for env_block in values.get("environment", []) or []:
        for env_var in env_block.get("environment_variable", []) or []:
            name = env_var.get("name", "")
            val = env_var.get("value", "") or ""
            var_type = env_var.get("type") or "PLAINTEXT"
            if var_type != "PLAINTEXT":
                continue
            if _SECRET_NAME_RE.search(name):
                suspicious_names.append(name)
            elif isinstance(val, str) and _SECRET_VALUE_RE.match(val):
                suspicious_values.append(name or "<unnamed>")

    passed = not (suspicious_names or suspicious_values)
    if passed:
        desc = "No plaintext environment variables with secret-like names or values detected."
    else:
        parts = []
        if suspicious_names:
            parts.append(f"secret-like names: {', '.join(suspicious_names)}")
        if suspicious_values:
            parts.append(
                f"credential-like values under: {', '.join(suspicious_values)}"
            )
        desc = (
            "Plaintext environment variables look like they contain secrets "
            f"({'; '.join(parts)}). Plaintext values are visible in the AWS "
            "console, CloudTrail, and build logs."
        )
    return Finding(
        check_id="CB-001",
        title="Secrets in plaintext environment variables",
        severity=Severity.CRITICAL,
        resource=address,
        description=desc,
        recommendation=(
            "Move secrets to AWS Secrets Manager or SSM Parameter Store and "
            "reference them using type SECRETS_MANAGER or PARAMETER_STORE."
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
        "access to the Docker daemon on the host."
    )
    return Finding(
        check_id="CB-002",
        title="Privileged mode enabled",
        severity=Severity.HIGH,
        resource=address,
        description=desc,
        recommendation=(
            "Disable privileged mode unless Docker-in-Docker is required."
        ),
        passed=not privileged,
    )


def _cb003_logging_enabled(values: dict, address: str) -> Finding:
    logs = _first(values.get("logs_config"))
    cw = _first(logs.get("cloudwatch_logs"))
    s3 = _first(logs.get("s3_logs"))
    # Terraform default for aws_codebuild_project: cloudwatch_logs status=ENABLED,
    # s3_logs status=DISABLED. Honour that when the sub-block is omitted.
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
            "Neither CloudWatch Logs nor S3 logging is enabled for this project."
        )
    return Finding(
        check_id="CB-003",
        title="Build logging not enabled",
        severity=Severity.MEDIUM,
        resource=address,
        description=desc,
        recommendation="Enable CloudWatch Logs or S3 logging in logs_config.",
        passed=passed,
    )


def _cb004_timeout(values: dict, address: str) -> Finding:
    timeout = values.get("build_timeout")
    passed = timeout is not None and timeout < _MAX_SENSIBLE_TIMEOUT
    desc = (
        f"Build timeout is set to {timeout} minutes."
        if passed else
        f"Build timeout is {timeout or 'default'} minutes (AWS maximum)."
    )
    return Finding(
        check_id="CB-004",
        title="No build timeout configured",
        severity=Severity.LOW,
        resource=address,
        description=desc,
        recommendation="Set a build timeout appropriate for expected build duration.",
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
        desc = f"Project uses a non-standard image ({image!r}); version check skipped."
    return Finding(
        check_id="CB-005",
        title="Outdated managed build image",
        severity=Severity.MEDIUM,
        resource=address,
        description=desc,
        recommendation=(
            f"Update the environment image to "
            f"aws/codebuild/standard:{_LATEST_STANDARD_VERSION}.0 or later."
        ),
        passed=passed,
    )


_LONG_LIVED_TOKEN_AUTH = {"OAUTH", "PERSONAL_ACCESS_TOKEN", "BASIC_AUTH"}
_EXTERNAL_SOURCE_TYPES = {"GITHUB", "GITHUB_ENTERPRISE", "BITBUCKET"}


def _cb006_source_auth(values: dict, source_creds: dict[str, str], address: str) -> Finding:
    source = _first(values.get("source"))
    src_type = source.get("type", "") or ""
    if src_type not in _EXTERNAL_SOURCE_TYPES:
        return Finding(
            check_id="CB-006",
            title="CodeBuild source auth uses long-lived token",
            severity=Severity.HIGH,
            resource=address,
            description=(
                f"Source type is {src_type or 'not external'}; long-lived-token "
                f"check not applicable."
            ),
            recommendation="No action required.",
            passed=True,
        )

    # In-project auth block (legacy)
    inline_auth = _first(source.get("auth"))
    inline_auth_type = inline_auth.get("type", "")

    # Side-resource aws_codebuild_source_credential
    side_auth_type = source_creds.get(src_type, "")

    offending = {
        t for t in (inline_auth_type, side_auth_type)
        if t in _LONG_LIVED_TOKEN_AUTH
    }
    passed = not offending

    if passed:
        desc = (
            f"Source ({src_type}) does not use a long-lived OAuth or PAT token "
            f"in its CodeBuild-managed credentials."
        )
    else:
        desc = (
            f"Project's {src_type} source auth uses {sorted(offending)}. "
            f"Long-lived OAuth/PAT tokens stored via aws_codebuild_source_credential "
            f"or inline source.auth expose the pipeline to credential theft and "
            f"don't rotate. Prefer short-lived CodeConnections (CodeStar) instead."
        )
    return Finding(
        check_id="CB-006",
        title="CodeBuild source auth uses long-lived token",
        severity=Severity.HIGH,
        resource=address,
        description=desc,
        recommendation=(
            "Replace OAuth/PAT auth with an AWS CodeConnections (CodeStar) "
            "connection and reference it from the project's source configuration."
        ),
        passed=passed,
    )


def _cb007_webhook_filter(webhook_values: dict | None, address: str) -> Finding:
    if webhook_values is None:
        return Finding(
            check_id="CB-007",
            title="CodeBuild webhook has no filter_group",
            severity=Severity.MEDIUM,
            resource=address,
            description="No aws_codebuild_webhook resource is defined for this project.",
            recommendation="No action required.",
            passed=True,
        )

    filter_groups = webhook_values.get("filter_group") or []
    passed = bool(filter_groups)
    desc = (
        f"Webhook for project defines {len(filter_groups)} filter_group(s)."
        if passed else
        "Webhook is attached to the project but has no filter_group. Any push "
        "event from any principal will trigger a build — including from forks "
        "for public repositories."
    )
    return Finding(
        check_id="CB-007",
        title="CodeBuild webhook has no filter_group",
        severity=Severity.MEDIUM,
        resource=address,
        description=desc,
        recommendation=(
            "Define filter_group blocks that restrict triggers to specific "
            "branches, actors, and event types. At minimum, include an "
            "ACTOR_ACCOUNT_ID filter to prevent fork-triggered builds."
        ),
        passed=passed,
    )
