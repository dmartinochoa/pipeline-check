"""CodeBuild security checks.

CB-001  Secrets in plaintext environment variables      CRITICAL  CICD-SEC-6
CB-002  Privileged mode enabled                         HIGH      CICD-SEC-7
CB-003  Build logging not enabled                       MEDIUM    CICD-SEC-10
CB-004  No build timeout configured                     LOW       CICD-SEC-7
CB-005  Outdated managed build image                    MEDIUM    CICD-SEC-7
CB-006  Source auth uses long-lived token               HIGH      CICD-SEC-6
CB-007  Webhook has no filter group                     MEDIUM    CICD-SEC-1

CB-001 matches **either** a secret-like variable name or a value that
matches a known credential pattern (AKIA/ASIA/ghp_/xoxb-/JWT).
"""

from botocore.exceptions import ClientError

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
from .base import AWSBaseCheck, Finding, Severity

_LONG_LIVED_TOKEN_AUTH = {"OAUTH", "PERSONAL_ACCESS_TOKEN", "BASIC_AUTH"}
_EXTERNAL_SOURCE_TYPES = {"GITHUB", "GITHUB_ENTERPRISE", "BITBUCKET"}

# Map source.type (used on projects) to the serverType values
# list_source_credentials returns.
_SOURCE_TYPE_TO_SERVER_TYPE = {
    "GITHUB": "GITHUB",
    "GITHUB_ENTERPRISE": "GITHUB_ENTERPRISE",
    "BITBUCKET": "BITBUCKET",
}

# Projects with a timeout at or above this are considered unconstrained.
_MAX_SENSIBLE_TIMEOUT = 480  # minutes (AWS maximum)


class CodeBuildChecks(AWSBaseCheck):
    """Runs all CB-XXX checks across every CodeBuild project in the region."""

    def run(self) -> list[Finding]:
        client = self.client("codebuild")

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

        source_creds = self._list_source_credentials(client)

        findings: list[Finding] = []
        # BatchGetProjects accepts up to 100 names per call.
        for i in range(0, len(project_names), 100):
            batch = project_names[i : i + 100]
            try:
                response = client.batch_get_projects(names=batch)
            except ClientError as exc:
                # Surface the dropped batch explicitly rather than
                # silently skipping 100 projects. A transient API
                # failure must not be indistinguishable from "all
                # projects clean".
                findings.append(Finding(
                    check_id="CB-000",
                    title="CodeBuild batch inspection failed",
                    severity=Severity.INFO,
                    resource=f"codebuild (projects {i}..{i + len(batch)})",
                    description=(
                        f"Could not BatchGetProjects for {len(batch)} "
                        f"project name(s): {exc}. Those projects were "
                        f"not evaluated by any CB-XXX check."
                    ),
                    recommendation=(
                        "Retry the scan; if the failure is persistent, "
                        "check IAM permissions for codebuild:BatchGetProjects "
                        "and CloudTrail for throttling."
                    ),
                    passed=False,
                ))
                continue
            for project in response.get("projects", []):
                findings.extend(self._check_project(project, source_creds))

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

    @staticmethod
    def _list_source_credentials(client) -> dict[str, set[str]]:
        """Return {serverType: {authType, ...}} for account-level stored creds."""
        by_server: dict[str, set[str]] = {}
        try:
            resp = client.list_source_credentials()
        except ClientError:
            return by_server
        for cred in resp.get("sourceCredentialsInfos", []):
            server = cred.get("serverType", "")
            auth = cred.get("authType", "")
            if server and auth:
                by_server.setdefault(server, set()).add(auth)
        return by_server

    def _check_project(
        self, project: dict, source_creds: dict[str, set[str]]
    ) -> list[Finding]:
        name: str = project["name"]
        return [
            self._cb001_plaintext_secrets(project, name),
            self._cb002_privileged_mode(project, name),
            self._cb003_logging_enabled(project, name),
            self._cb004_timeout(project, name),
            self._cb005_image_version(project, name),
            self._cb006_source_auth(project, name, source_creds),
            self._cb007_webhook_filter(project, name),
        ]

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    @staticmethod
    def _cb001_plaintext_secrets(project: dict, name: str) -> Finding:
        env_vars: list[dict] = project.get("environment", {}).get(
            "environmentVariables", []
        )
        suspicious_names: list[str] = []
        suspicious_values: list[str] = []
        for v in env_vars:
            if v.get("type", "PLAINTEXT") != "PLAINTEXT":
                continue
            vname = v.get("name", "")
            vval = v.get("value", "") or ""
            if _SECRET_NAME_RE.search(vname):
                suspicious_names.append(vname)
            elif isinstance(vval, str) and _SECRET_VALUE_RE.match(vval):
                suspicious_values.append(vname or "<unnamed>")
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
                f"Plaintext environment variables appear to contain secrets "
                f"({'; '.join(parts)})."
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

    @staticmethod
    def _cb006_source_auth(
        project: dict, name: str, source_creds: dict[str, set[str]]
    ) -> Finding:
        source = project.get("source", {}) or {}
        src_type = source.get("type", "") or ""
        if src_type not in _EXTERNAL_SOURCE_TYPES:
            return Finding(
                check_id="CB-006",
                title="CodeBuild source auth uses long-lived token",
                severity=Severity.HIGH,
                resource=name,
                description=(
                    f"Source type is {src_type or 'not external'}; check not applicable."
                ),
                recommendation="No action required.",
                passed=True,
            )
        inline_auth = (source.get("auth") or {}).get("type", "")
        stored_auths = source_creds.get(
            _SOURCE_TYPE_TO_SERVER_TYPE.get(src_type, src_type), set()
        )
        stored_offending = sorted(stored_auths & _LONG_LIVED_TOKEN_AUTH)
        inline_offending = inline_auth in _LONG_LIVED_TOKEN_AUTH
        passed = not (inline_offending or stored_offending)

        if passed:
            desc = f"Source ({src_type}) auth type is {inline_auth or 'not set'}."
        else:
            parts = []
            if inline_offending:
                parts.append(f"inline auth {inline_auth}")
            if stored_offending:
                parts.append(
                    f"account-level source credential(s) "
                    f"({', '.join(stored_offending)}) for {src_type}"
                )
            desc = (
                f"Source ({src_type}) authenticates via long-lived token(s): "
                f"{'; '.join(parts)}. These don't rotate and expose the pipeline "
                f"to credential theft."
            )
        return Finding(
            check_id="CB-006",
            title="CodeBuild source auth uses long-lived token",
            severity=Severity.HIGH,
            resource=name,
            description=desc,
            recommendation=(
                "Switch to an AWS CodeConnections (CodeStar) connection and "
                "reference it from the source configuration. Delete any stored "
                "source credentials of type OAUTH, PERSONAL_ACCESS_TOKEN, or "
                "BASIC_AUTH via delete_source_credentials."
            ),
            passed=passed,
        )

    @staticmethod
    def _cb007_webhook_filter(project: dict, name: str) -> Finding:
        webhook = project.get("webhook")
        if not webhook:
            return Finding(
                check_id="CB-007",
                title="CodeBuild webhook has no filter group",
                severity=Severity.MEDIUM,
                resource=name,
                description="No webhook is attached to this project.",
                recommendation="No action required.",
                passed=True,
            )
        groups = webhook.get("filterGroups") or []
        passed = bool(groups)
        desc = (
            f"Webhook defines {len(groups)} filter group(s)."
            if passed else
            "Webhook is attached but has no filter group. Any push from any "
            "principal will trigger a build."
        )
        return Finding(
            check_id="CB-007",
            title="CodeBuild webhook has no filter group",
            severity=Severity.MEDIUM,
            resource=name,
            description=desc,
            recommendation=(
                "Define filter groups restricting triggers to specific branches, "
                "actors, and event types."
            ),
            passed=passed,
        )
