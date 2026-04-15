"""Terraform CodePipeline checks (CP-001 … CP-003).

Mirrors the AWS-provider semantics against the ``aws_codepipeline`` resource
schema emitted by ``terraform show -json``.
"""
from __future__ import annotations

from .base import TerraformBaseCheck
from ..base import Finding, Severity


class CodePipelineChecks(TerraformBaseCheck):

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for r in self.ctx.resources("aws_codepipeline"):
            name = r.values.get("name") or r.name
            stages = r.values.get("stage", []) or []
            findings.extend([
                _cp001_approval_before_deploy(stages, name),
                _cp002_artifact_encryption(r.values, name),
                _cp003_source_polling(stages, name),
            ])
        return findings


def _cp001_approval_before_deploy(stages: list[dict], name: str) -> Finding:
    approval_seen = False
    deploy_without_approval = False
    for stage in stages:
        for action in stage.get("action", []) or []:
            category = action.get("category", "")
            if category == "Approval":
                approval_seen = True
            if category == "Deploy" and not approval_seen:
                deploy_without_approval = True

    passed = not deploy_without_approval
    desc = (
        "At least one manual approval action exists before all deploy stages."
        if passed else
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


def _cp002_artifact_encryption(values: dict, name: str) -> Finding:
    stores = values.get("artifact_store", []) or []
    unencrypted = []
    for s in stores:
        ek = s.get("encryption_key") or []
        if not ek:
            unencrypted.append(s.get("location", "unknown"))
    passed = not unencrypted
    desc = (
        "All artifact stores use a customer-managed KMS encryption key."
        if passed else
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
            "Configure a customer-managed AWS KMS key as the encryption_key for "
            "each artifact_store block."
        ),
        passed=passed,
    )


def _cp003_source_polling(stages: list[dict], name: str) -> Finding:
    polling_sources: list[str] = []
    for stage in stages:
        for action in stage.get("action", []) or []:
            if action.get("category") != "Source":
                continue
            config = action.get("configuration", {}) or {}
            if str(config.get("PollForSourceChanges", "")).lower() == "true":
                polling_sources.append(action.get("name", "unnamed"))

    passed = not polling_sources
    desc = (
        "All source actions use event-driven change detection."
        if passed else
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
            "rule or CodeCommit trigger to start the pipeline on change."
        ),
        passed=passed,
    )
