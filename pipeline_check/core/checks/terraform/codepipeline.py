"""Terraform CodePipeline checks.

CP-001  No approval action before deploy stages             HIGH      CICD-SEC-1
CP-002  Artifact store not encrypted with customer KMS key  MEDIUM    CICD-SEC-9
CP-003  Source stage using polling                          LOW       CICD-SEC-4
CP-004  Legacy ThirdParty/GitHub (OAuth) source action      HIGH      CICD-SEC-6
"""
from __future__ import annotations

from typing import Any

from ..base import Finding, Severity
from .base import TerraformBaseCheck


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
                _cp004_legacy_github(stages, name),
            ])
        return findings


def _run_order(action: dict[str, Any]) -> int:
    """A stage action's run_order, defaulting to 1 (CodePipeline's default)."""
    try:
        return int(action.get("run_order") or 1)
    except (TypeError, ValueError):
        return 1


def _cp001_approval_before_deploy(stages: list[dict[str, Any]], name: str) -> Finding:
    # An approval only gates a deploy that actually runs after it.
    # Actions in the same stage with an equal run_order run in parallel,
    # so a same-stage Approval listed before a Deploy does NOT gate it;
    # only a strictly lower run_order (or an approval in a prior stage)
    # does.
    approval_from_prior_stage = False
    deploy_without_approval = False
    for stage in stages:
        actions = stage.get("action", []) or []
        approval_run_orders = [
            _run_order(a) for a in actions if a.get("category", "") == "Approval"
        ]
        for action in actions:
            if action.get("category", "") != "Deploy":
                continue
            deploy_ro = _run_order(action)
            gated_in_stage = any(ro < deploy_ro for ro in approval_run_orders)
            if not (approval_from_prior_stage or gated_in_stage):
                deploy_without_approval = True
        if approval_run_orders:
            approval_from_prior_stage = True

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


def _is_customer_managed_key(encryption_key: object) -> bool:
    """True only for a KMS key that isn't an AWS-managed alias.

    An ``encryption_key`` of ``alias/aws/s3`` (or any ``alias/aws/*``)
    is the AWS-managed key, not a customer-managed one, so it doesn't
    satisfy the rule. Mirrors the ``alias/aws/`` rejection in the
    sibling CA-001 / CCM-002 / SSM-002 checks.
    """
    if not isinstance(encryption_key, list) or not encryption_key:
        return False
    head = encryption_key[0] if isinstance(encryption_key[0], dict) else {}
    key_id = str(head.get("id", ""))
    return not key_id.startswith("alias/aws/")


def _cp002_artifact_encryption(values: dict[str, Any], name: str) -> Finding:
    stores = values.get("artifact_store", []) or []
    unencrypted = [
        s.get("location", "unknown")
        for s in stores
        if not _is_customer_managed_key(s.get("encryption_key"))
    ]
    passed = not unencrypted
    desc = (
        "All artifact stores use a customer-managed KMS encryption key."
        if passed else
        f"Artifact store(s) {unencrypted} rely on default S3 SSE rather than "
        f"a customer-managed KMS key."
    )
    return Finding(
        check_id="CP-002",
        title="Artifact store not encrypted with customer-managed KMS key",
        severity=Severity.MEDIUM,
        resource=name,
        description=desc,
        recommendation="Set encryption_key on each artifact_store block.",
        passed=passed,
    )


def _cp003_source_polling(stages: list[dict[str, Any]], name: str) -> Finding:
    polling = []
    for stage in stages:
        for action in stage.get("action", []) or []:
            if action.get("category") != "Source":
                continue
            config = action.get("configuration", {}) or {}
            if str(config.get("PollForSourceChanges", "")).lower() == "true":
                polling.append(action.get("name", "unnamed"))

    passed = not polling
    desc = (
        "All source actions use event-driven change detection."
        if passed else
        f"Source action(s) {polling} use polling."
    )
    return Finding(
        check_id="CP-003",
        title="Source stage using polling instead of event-driven trigger",
        severity=Severity.LOW,
        resource=name,
        description=desc,
        recommendation=(
            "Set PollForSourceChanges=false and use an EventBridge rule."
        ),
        passed=passed,
    )


def _cp004_legacy_github(stages: list[dict[str, Any]], name: str) -> Finding:
    legacy = []
    for stage in stages:
        for action in stage.get("action", []) or []:
            if action.get("category") != "Source":
                continue
            owner = action.get("owner", "")
            provider = action.get("provider", "")
            if owner == "ThirdParty" and provider == "GitHub":
                legacy.append(action.get("name", "unnamed"))

    passed = not legacy
    desc = (
        "No legacy ThirdParty/GitHub (v1) source actions detected."
        if passed else
        f"Source action(s) {legacy} use the deprecated ThirdParty/GitHub v1 "
        f"provider, which authenticates via a long-lived OAuth token stored "
        f"in the pipeline configuration."
    )
    return Finding(
        check_id="CP-004",
        title="Legacy ThirdParty/GitHub source action (OAuth token)",
        severity=Severity.HIGH,
        resource=name,
        description=desc,
        recommendation=(
            "Migrate to owner=AWS, provider=CodeStarSourceConnection and "
            "reference a CodeConnections connection ARN. This replaces the "
            "long-lived token with short-lived, revocable credentials."
        ),
        passed=passed,
    )
