"""CloudFormation CodePipeline checks — CP-001..004."""
from __future__ import annotations

from ..base import Finding, Severity
from .base import CloudFormationBaseCheck, as_str, is_intrinsic


class CodePipelineChecks(CloudFormationBaseCheck):

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for r in self.ctx.resources("AWS::CodePipeline::Pipeline"):
            name = as_str(r.properties.get("Name")) or r.logical_id
            stages = r.properties.get("Stages") or []
            findings.extend([
                _cp001_approval_before_deploy(stages, name),
                _cp002_artifact_encryption(r.properties, name),
                _cp003_source_polling(stages, name),
                _cp004_legacy_github(stages, name),
            ])
        return findings


def _cp001_approval_before_deploy(stages: list, name: str) -> Finding:
    approval_seen = False
    deploy_without_approval = False
    for stage in stages:
        if not isinstance(stage, dict):
            continue
        for action in stage.get("Actions", []) or []:
            if not isinstance(action, dict):
                continue
            type_id = action.get("ActionTypeId") or {}
            category = as_str(type_id.get("Category"))
            if category == "Approval":
                approval_seen = True
            if category == "Deploy" and not approval_seen:
                deploy_without_approval = True
    passed = not deploy_without_approval
    desc = (
        "At least one manual approval action exists before all deploy stages."
        if passed else
        "One or more Deploy stages are reachable without a preceding Manual approval action."
    )
    return Finding(
        check_id="CP-001",
        title="No approval action before deploy stages",
        severity=Severity.HIGH,
        resource=name,
        description=desc,
        recommendation=(
            "Add a Manual approval action to a stage that precedes every Deploy stage."
        ),
        passed=passed,
    )


def _cp002_artifact_encryption(properties: dict, name: str) -> Finding:
    # CFN supports both ArtifactStore (singular) and ArtifactStores (plural map).
    stores: list[dict] = []
    single = properties.get("ArtifactStore")
    if isinstance(single, dict) and not is_intrinsic(single):
        stores.append(single)
    plural = properties.get("ArtifactStores")
    if isinstance(plural, list):
        for entry in plural:
            if isinstance(entry, dict) and isinstance(entry.get("ArtifactStore"), dict):
                stores.append(entry["ArtifactStore"])
    elif isinstance(plural, dict):
        for entry in plural.values():
            if isinstance(entry, dict):
                stores.append(entry)
    if not stores:
        return Finding(
            check_id="CP-002",
            title="Artifact store not encrypted with customer-managed KMS key",
            severity=Severity.MEDIUM,
            resource=name,
            description="Pipeline declares no ArtifactStore property.",
            recommendation="Set ArtifactStore.EncryptionKey to a customer-managed KMS key.",
            passed=False,
        )
    unencrypted = [
        as_str(s.get("Location")) or "<unnamed>"
        for s in stores
        if not s.get("EncryptionKey")
    ]
    passed = not unencrypted
    desc = (
        "All artifact stores use a customer-managed KMS encryption key."
        if passed else
        f"Artifact store(s) {unencrypted} rely on default S3 SSE rather than "
        "a customer-managed KMS key."
    )
    return Finding(
        check_id="CP-002",
        title="Artifact store not encrypted with customer-managed KMS key",
        severity=Severity.MEDIUM,
        resource=name,
        description=desc,
        recommendation="Set EncryptionKey on each ArtifactStore.",
        passed=passed,
    )


def _cp003_source_polling(stages: list, name: str) -> Finding:
    polling_actions: list[str] = []
    for stage in stages:
        if not isinstance(stage, dict):
            continue
        for action in stage.get("Actions", []) or []:
            if not isinstance(action, dict):
                continue
            type_id = action.get("ActionTypeId") or {}
            if as_str(type_id.get("Category")) != "Source":
                continue
            config = action.get("Configuration") or {}
            # Both ``true`` (boolean) and ``"true"`` (string) appear in CFN.
            poll = config.get("PollForSourceChanges")
            poll_bool = poll is True or (
                isinstance(poll, str) and poll.lower() == "true"
            )
            if poll_bool:
                polling_actions.append(as_str(action.get("Name")) or "<unnamed>")
    passed = not polling_actions
    desc = (
        "Source actions use event-driven triggers (no polling)."
        if passed else
        f"Source action(s) {polling_actions} use PollForSourceChanges=true."
    )
    return Finding(
        check_id="CP-003",
        title="Source stage using polling",
        severity=Severity.LOW,
        resource=name,
        description=desc,
        recommendation=(
            "Remove PollForSourceChanges or set it to false, and rely on "
            "CodeCommit triggers / CodeConnections webhooks for event-driven "
            "pipeline starts."
        ),
        passed=passed,
    )


def _cp004_legacy_github(stages: list, name: str) -> Finding:
    offenders: list[str] = []
    for stage in stages:
        if not isinstance(stage, dict):
            continue
        for action in stage.get("Actions", []) or []:
            if not isinstance(action, dict):
                continue
            type_id = action.get("ActionTypeId") or {}
            owner = as_str(type_id.get("Owner"))
            provider = as_str(type_id.get("Provider"))
            # The legacy OAuth GitHub source action is ``Owner: ThirdParty,
            # Provider: GitHub``. The modern replacement is ``Owner: AWS,
            # Provider: CodeStarSourceConnection``.
            if owner == "ThirdParty" and provider == "GitHub":
                offenders.append(as_str(action.get("Name")) or "<unnamed>")
    passed = not offenders
    desc = (
        "No pipeline action uses the legacy ThirdParty/GitHub source integration."
        if passed else
        f"Action(s) {offenders} use the legacy ThirdParty/GitHub OAuth source."
    )
    return Finding(
        check_id="CP-004",
        title="Legacy ThirdParty/GitHub (OAuth) source action",
        severity=Severity.HIGH,
        resource=name,
        description=desc,
        recommendation=(
            "Replace the ThirdParty/GitHub source action with "
            "AWS/CodeStarSourceConnection and reference an AWS CodeConnections "
            "connection ARN in the action configuration."
        ),
        passed=passed,
    )
