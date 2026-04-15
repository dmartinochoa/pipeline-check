"""CodePipeline security checks.

CP-001  No approval action before deploy stages          HIGH    CICD-SEC-1
CP-002  Artifact store not encrypted with KMS            MEDIUM  CICD-SEC-9
CP-003  Source stage using polling instead of events     LOW     CICD-SEC-4
CP-004  Legacy ThirdParty/GitHub (OAuth token) source    HIGH    CICD-SEC-6
"""

from botocore.exceptions import ClientError

from .base import AWSBaseCheck, Finding, Severity


class CodePipelineChecks(AWSBaseCheck):

    def run(self) -> list[Finding]:
        client = self.client("codepipeline")

        if self.target:
            pipelines = [self.target]
        else:
            try:
                pipelines = self._list_pipelines(client)
            except ClientError as exc:
                return [Finding(
                    check_id="CP-000",
                    title="CodePipeline API access failed",
                    severity=Severity.INFO,
                    resource="codepipeline",
                    description=f"Could not list pipelines: {exc}. CP checks skipped.",
                    recommendation=(
                        "Ensure the IAM principal has codepipeline:ListPipelines and "
                        "codepipeline:GetPipeline permissions."
                    ),
                    passed=False,
                )]

        findings: list[Finding] = []
        for name in pipelines:
            try:
                resp = client.get_pipeline(name=name)
                pipeline = resp["pipeline"]
            except ClientError as exc:
                findings.append(Finding(
                    check_id="CP-000",
                    title="CodePipeline inspection degraded",
                    severity=Severity.INFO,
                    resource=f"codepipeline/{name}",
                    description=(
                        f"Could not fetch pipeline {name}: {exc}. "
                        f"CP-001..004 were not evaluated for this pipeline."
                    ),
                    recommendation=(
                        "Retry the scan; if the failure is persistent check "
                        "IAM permissions for codepipeline:GetPipeline."
                    ),
                    passed=False,
                ))
                continue
            findings.extend(self._check_pipeline(pipeline))

        return findings

    @staticmethod
    def _list_pipelines(client) -> list[str]:
        names: list[str] = []
        paginator = client.get_paginator("list_pipelines")
        for page in paginator.paginate():
            names.extend(p["name"] for p in page.get("pipelines", []))
        return names

    def _check_pipeline(self, pipeline: dict) -> list[Finding]:
        name = pipeline["name"]
        stages: list[dict] = pipeline.get("stages", [])
        return [
            self._cp001_approval_before_deploy(stages, name),
            self._cp002_artifact_encryption(pipeline, name),
            self._cp003_source_polling(stages, name),
            self._cp004_legacy_github(stages, name),
        ]

    @staticmethod
    def _cp004_legacy_github(stages: list[dict], name: str) -> Finding:
        legacy: list[str] = []
        for stage in stages:
            for action in stage.get("actions", []):
                type_id = action.get("actionTypeId", {})
                if type_id.get("owner") == "ThirdParty" and type_id.get("provider") == "GitHub":
                    legacy.append(action.get("name", "unnamed"))
        passed = not legacy
        desc = (
            "No legacy ThirdParty/GitHub (v1) source actions detected."
            if passed else
            f"Source action(s) {legacy} use the deprecated ThirdParty/GitHub v1 "
            f"provider, which authenticates via a long-lived OAuth token."
        )
        return Finding(
            check_id="CP-004",
            title="Legacy ThirdParty/GitHub source action (OAuth token)",
            severity=Severity.HIGH,
            resource=name,
            description=desc,
            recommendation=(
                "Migrate to owner=AWS, provider=CodeStarSourceConnection and "
                "reference a CodeConnections connection ARN."
            ),
            passed=passed,
        )

    @staticmethod
    def _cp001_approval_before_deploy(stages: list[dict], name: str) -> Finding:
        """Fail if any Deploy stage has no prior Manual approval action."""
        approval_seen = False
        deploy_without_approval = False

        for stage in stages:
            for action in stage.get("actions", []):
                category = action.get("actionTypeId", {}).get("category", "")
                if category == "Approval":
                    approval_seen = True
                if category == "Deploy" and not approval_seen:
                    deploy_without_approval = True

        passed = not deploy_without_approval

        if passed:
            desc = "At least one manual approval action exists before all deploy stages."
        else:
            desc = (
                "One or more Deploy stages are reachable without a preceding Manual "
                "approval action. This allows any code change to reach production "
                "automatically without human review, violating flow control principles."
            )

        return Finding(
            check_id="CP-001",
            title="No approval action before deploy stages",
            severity=Severity.HIGH,
            resource=name,
            description=desc,
            recommendation=(
                "Add a Manual approval action to a stage that precedes every Deploy "
                "stage that targets a production or sensitive environment."
            ),
            passed=passed,
        )

    @staticmethod
    def _cp002_artifact_encryption(pipeline: dict, name: str) -> Finding:
        """Fail if the artifact store does not use a customer-managed KMS key."""
        stores: list[dict] = []

        # Single artifact store (legacy)
        if "artifactStore" in pipeline:
            stores.append(pipeline["artifactStore"])
        # Per-region artifact stores
        stores.extend(pipeline.get("artifactStores", {}).values())

        unencrypted = [
            s.get("location", "unknown")
            for s in stores
            if "encryptionKey" not in s
        ]
        passed = not unencrypted

        if passed:
            desc = "All artifact stores use a customer-managed KMS encryption key."
        else:
            desc = (
                f"Artifact store(s) {unencrypted} rely on default S3 SSE (AWS-managed "
                f"key) rather than a customer-managed KMS key. This reduces auditability "
                f"and control over who can decrypt pipeline artifacts."
            )

        return Finding(
            check_id="CP-002",
            title="Artifact store not encrypted with customer-managed KMS key",
            severity=Severity.MEDIUM,
            resource=name,
            description=desc,
            recommendation=(
                "Configure a customer-managed AWS KMS key as the encryptionKey for "
                "each artifact store. This enables key rotation, fine-grained access "
                "policies, and CloudTrail auditing of decrypt operations."
            ),
            passed=passed,
        )

    @staticmethod
    def _cp003_source_polling(stages: list[dict], name: str) -> Finding:
        """Fail if any source action uses polling instead of event-driven detection."""
        polling_sources: list[str] = []

        for stage in stages:
            for action in stage.get("actions", []):
                category = action.get("actionTypeId", {}).get("category", "")
                if category != "Source":
                    continue
                config = action.get("configuration", {})
                # CodeCommit and S3 sources expose PollForSourceChanges explicitly.
                if config.get("PollForSourceChanges", "").lower() == "true":
                    polling_sources.append(action.get("name", "unnamed"))

        passed = not polling_sources

        if passed:
            desc = "All source actions use event-driven change detection."
        else:
            desc = (
                f"Source action(s) {polling_sources} use polling "
                f"(PollForSourceChanges=true). Polling-based triggers have higher "
                f"latency, consume API quota, and may miss rapid successive changes."
            )

        return Finding(
            check_id="CP-003",
            title="Source stage using polling instead of event-driven trigger",
            severity=Severity.LOW,
            resource=name,
            description=desc,
            recommendation=(
                "Set PollForSourceChanges=false and configure an Amazon EventBridge "
                "rule or CodeCommit trigger to start the pipeline on change. This "
                "reduces latency, API usage, and improves auditability."
            ),
            passed=passed,
        )
