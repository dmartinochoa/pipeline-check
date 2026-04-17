"""CloudFormation CodeBuild checks — mirror of the Terraform CB-001..007.

Same check IDs, same logic, same severities. Resource-type mapping:

    Terraform                          CloudFormation
    aws_codebuild_project              AWS::CodeBuild::Project
    aws_codebuild_source_credential    AWS::CodeBuild::SourceCredential
    aws_codebuild_webhook              AWS::CodeBuild::Project (Triggers prop)

Property-name translation is snake_case → PascalCase. Webhook settings
are a property of the Project resource in CFN, not a separate resource.
"""
from __future__ import annotations

from .._patterns import (
    LATEST_STANDARD_VERSION as _LATEST_STANDARD_VERSION,
)
from .._patterns import (
    MANAGED_IMAGE_RE as _MANAGED_IMAGE_RE,
)
from .._patterns import (
    SECRET_NAME_RE as _SECRET_NAME_RE,
)
from .._patterns import (
    SECRET_VALUE_RE as _SECRET_VALUE_RE,
)
from ..base import Finding, Severity
from .base import CloudFormationBaseCheck, as_str, is_intrinsic, is_true

_MAX_SENSIBLE_TIMEOUT = 480
_LONG_LIVED_TOKEN_AUTH = {"OAUTH", "PERSONAL_ACCESS_TOKEN", "BASIC_AUTH"}
_EXTERNAL_SOURCE_TYPES = {"GITHUB", "GITHUB_ENTERPRISE", "BITBUCKET"}


class CodeBuildChecks(CloudFormationBaseCheck):

    def run(self) -> list[Finding]:
        # CB-006 side resources.
        source_creds: dict[str, str] = {}
        for r in self.ctx.resources("AWS::CodeBuild::SourceCredential"):
            server = as_str(r.properties.get("ServerType"))
            auth = as_str(r.properties.get("AuthType"))
            if server and auth:
                source_creds[server] = auth

        findings: list[Finding] = []
        for r in self.ctx.resources("AWS::CodeBuild::Project"):
            findings.extend([
                _cb001_plaintext_secrets(r.properties, r.address),
                _cb002_privileged_mode(r.properties, r.address),
                _cb003_logging_enabled(r.properties, r.address),
                _cb004_timeout(r.properties, r.address),
                _cb005_image_version(r.properties, r.address),
                _cb006_source_auth(r.properties, source_creds, r.address),
                _cb007_webhook_filter(r.properties, r.address),
            ])
        return findings


def _cb001_plaintext_secrets(properties: dict, address: str) -> Finding:
    env = properties.get("Environment") or {}
    if is_intrinsic(env):
        env = {}
    suspicious_names: list[str] = []
    suspicious_values: list[str] = []
    for ev in env.get("EnvironmentVariables", []) or []:
        if not isinstance(ev, dict):
            continue
        var_type = as_str(ev.get("Type")) or "PLAINTEXT"
        if var_type != "PLAINTEXT":
            continue
        name = as_str(ev.get("Name"))
        val = ev.get("Value")
        val_str = as_str(val)
        if name and _SECRET_NAME_RE.search(name):
            suspicious_names.append(name)
        elif val_str and _SECRET_VALUE_RE.match(val_str):
            suspicious_values.append(name or "<unnamed>")
    passed = not (suspicious_names or suspicious_values)
    if passed:
        desc = "No plaintext environment variables with secret-like names or values detected."
    else:
        parts = []
        if suspicious_names:
            parts.append(f"secret-like names: {', '.join(suspicious_names)}")
        if suspicious_values:
            parts.append(f"credential-like values under: {', '.join(suspicious_values)}")
        desc = (
            "Plaintext environment variables look like they contain secrets "
            f"({'; '.join(parts)})."
        )
    return Finding(
        check_id="CB-001",
        title="Secrets in plaintext environment variables",
        severity=Severity.CRITICAL,
        resource=address,
        description=desc,
        recommendation=(
            "Set Type: SECRETS_MANAGER or PARAMETER_STORE on environment "
            "variables sourced from AWS Secrets Manager or SSM Parameter Store."
        ),
        passed=passed,
    )


def _cb002_privileged_mode(properties: dict, address: str) -> Finding:
    env = properties.get("Environment") or {}
    privileged = is_true(env.get("PrivilegedMode"))
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
            "Set Environment.PrivilegedMode: false unless Docker-in-Docker is required."
        ),
        passed=not privileged,
    )


def _cb003_logging_enabled(properties: dict, address: str) -> Finding:
    logs = properties.get("LogsConfig") or {}
    cw = logs.get("CloudWatchLogs") or {}
    s3 = logs.get("S3Logs") or {}
    # CFN default: CloudWatchLogs Status defaults to ENABLED if the
    # LogsConfig is present but Status is absent. If the whole LogsConfig
    # is missing, CW is still enabled by default (AWS service-level).
    cw_status = as_str(cw.get("Status")) or "ENABLED"
    s3_status = as_str(s3.get("Status")) or "DISABLED"
    cw_enabled = cw_status == "ENABLED"
    s3_enabled = s3_status == "ENABLED"
    passed = cw_enabled or s3_enabled
    if passed:
        dest = []
        if cw_enabled:
            dest.append("CloudWatch Logs")
        if s3_enabled:
            dest.append("S3")
        desc = f"Build logging is enabled ({' and '.join(dest)})."
    else:
        desc = "Neither CloudWatch Logs nor S3 logging is enabled for this project."
    return Finding(
        check_id="CB-003",
        title="Build logging not enabled",
        severity=Severity.MEDIUM,
        resource=address,
        description=desc,
        recommendation="Enable CloudWatch Logs or S3 logging in LogsConfig.",
        passed=passed,
    )


def _cb004_timeout(properties: dict, address: str) -> Finding:
    timeout = properties.get("TimeoutInMinutes")
    # CFN accepts both an integer (``TimeoutInMinutes: 30``) and its
    # stringified form (``TimeoutInMinutes: "30"``) — the latter is
    # common when the value comes from a parameter default. Normalise
    # both before the threshold comparison so a valid string doesn't
    # false-positive.
    numeric_value: float | None = None
    if isinstance(timeout, (int, float)):
        numeric_value = float(timeout)
    elif isinstance(timeout, str):
        try:
            numeric_value = float(timeout.strip())
        except ValueError:
            numeric_value = None
    passed = numeric_value is not None and numeric_value < _MAX_SENSIBLE_TIMEOUT
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
        recommendation="Set TimeoutInMinutes to a finite value below the 480-minute ceiling.",
        passed=passed,
    )


def _cb005_image_version(properties: dict, address: str) -> Finding:
    env = properties.get("Environment") or {}
    image = as_str(env.get("Image"))
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
            f"Update Environment.Image to "
            f"aws/codebuild/standard:{_LATEST_STANDARD_VERSION}.0 or later."
        ),
        passed=passed,
    )


def _cb006_source_auth(
    properties: dict, source_creds: dict[str, str], address: str,
) -> Finding:
    source = properties.get("Source") or {}
    if is_intrinsic(source):
        source = {}
    src_type = as_str(source.get("Type"))
    if src_type not in _EXTERNAL_SOURCE_TYPES:
        return Finding(
            check_id="CB-006",
            title="CodeBuild source auth uses long-lived token",
            severity=Severity.HIGH,
            resource=address,
            description=(
                f"Source type is {src_type or 'not external'}; long-lived-token "
                "check not applicable."
            ),
            recommendation="No action required.",
            passed=True,
        )

    inline_auth = source.get("Auth") or {}
    inline_auth_type = as_str(inline_auth.get("Type"))
    side_auth_type = source_creds.get(src_type, "")
    offending = {
        t for t in (inline_auth_type, side_auth_type)
        if t in _LONG_LIVED_TOKEN_AUTH
    }
    passed = not offending
    if passed:
        desc = (
            f"Source ({src_type}) does not use a long-lived OAuth or PAT token."
        )
    else:
        desc = (
            f"Project's {src_type} source auth uses {sorted(offending)}. "
            "Long-lived OAuth/PAT tokens don't rotate and expose the pipeline "
            "to credential theft. Prefer short-lived CodeConnections (CodeStar)."
        )
    return Finding(
        check_id="CB-006",
        title="CodeBuild source auth uses long-lived token",
        severity=Severity.HIGH,
        resource=address,
        description=desc,
        recommendation=(
            "Replace OAuth/PAT auth with an AWS CodeConnections (CodeStar) "
            "connection and reference it from the project's Source configuration."
        ),
        passed=passed,
    )


def _cb007_webhook_filter(properties: dict, address: str) -> Finding:
    triggers = properties.get("Triggers") or {}
    if is_intrinsic(triggers):
        triggers = {}
    webhook_on = is_true(triggers.get("Webhook"))
    if not webhook_on:
        return Finding(
            check_id="CB-007",
            title="CodeBuild webhook has no filter_group",
            severity=Severity.MEDIUM,
            resource=address,
            description="No webhook is enabled on this project.",
            recommendation="No action required.",
            passed=True,
        )
    filter_groups = triggers.get("FilterGroups") or []
    passed = bool(filter_groups)
    desc = (
        f"Webhook for project defines {len(filter_groups)} filter group(s)."
        if passed else
        "Webhook is enabled but has no FilterGroups. Any push event from any "
        "principal will trigger a build — including from forks for public repos."
    )
    return Finding(
        check_id="CB-007",
        title="CodeBuild webhook has no filter_group",
        severity=Severity.MEDIUM,
        resource=address,
        description=desc,
        recommendation=(
            "Set Triggers.FilterGroups that restrict triggers to specific "
            "branches, actors, and event types. At minimum include an "
            "ACTOR_ACCOUNT_ID filter to prevent fork-triggered builds."
        ),
        passed=passed,
    )
