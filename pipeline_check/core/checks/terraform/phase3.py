"""Phase-3 Terraform parity: deeper detections that translate to HCL.

Runtime-only Phase-3 checks (Inspector v2 account status, Signer
profile revocation, CloudWatch alarm coverage, EventBridge target
ARNs) have no useful Terraform analogue and are omitted.
"""
from __future__ import annotations

import json

from ..base import Finding, Severity
from .base import TerraformBaseCheck

_PR_EVENTS = {
    "PULL_REQUEST_CREATED", "PULL_REQUEST_UPDATED", "PULL_REQUEST_REOPENED",
}
_PROD_TOKENS = ("prod", "production", "live")
_ECR_TRUSTED_UPSTREAMS = {
    "public.ecr.aws", "registry.k8s.io", "ghcr.io", "gcr.io",
}


class Phase3Checks(TerraformBaseCheck):

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(_ecr006(self.ctx))
        findings.extend(_pbac003(self.ctx))
        findings.extend(_pbac005_cp005_cp007(self.ctx))
        findings.extend(_eb001(self.ctx))
        return findings


def _ecr006(ctx) -> list[Finding]:
    out: list[Finding] = []
    for r in ctx.resources("aws_ecr_pull_through_cache_rule"):
        upstream = r.values.get("upstream_registry_url", "") or ""
        has_cred = bool(r.values.get("credential_arn"))
        passed = upstream in _ECR_TRUSTED_UPSTREAMS or has_cred
        out.append(Finding(
            check_id="ECR-006",
            title="ECR pull-through cache rule uses an untrusted upstream",
            severity=Severity.HIGH,
            resource=r.address,
            description=(
                f"Upstream {upstream} is trusted or authenticated." if passed else
                f"Upstream {upstream!r} is unauthenticated and not on the trusted allow-list."
            ),
            recommendation="Scope upstreams to trusted registries or add credential_arn.",
            passed=passed,
        ))
    return out


def _pbac003(ctx) -> list[Finding]:
    out: list[Finding] = []
    for sg in ctx.resources("aws_security_group"):
        for rule in sg.values.get("egress") or []:
            cidrs = rule.get("cidr_blocks") or []
            proto = rule.get("protocol", "") or ""
            from_p = rule.get("from_port")
            to_p = rule.get("to_port")
            if "0.0.0.0/0" in cidrs and (
                proto in ("-1", "all") or (from_p in (0, None) and to_p in (65535, None))
            ):
                out.append(Finding(
                    check_id="PBAC-003",
                    title="Security group allows 0.0.0.0/0 all-port egress",
                    severity=Severity.MEDIUM,
                    resource=sg.address,
                    description="Egress rule allows 0.0.0.0/0 on all ports.",
                    recommendation="Scope egress to specific destinations/ports.",
                    passed=False,
                ))
                break
    return out


def _pbac005_cp005_cp007(ctx) -> list[Finding]:
    out: list[Finding] = []
    for p in ctx.resources("aws_codepipeline"):
        name = p.values.get("name") or p.name
        pipeline_role = p.values.get("role_arn", "")
        stages = p.values.get("stage") or []
        # PBAC-005 — any stage action with its own role_arn passes.
        has_scoped = False
        total_actions = 0
        for stage in stages:
            for action in stage.get("action") or []:
                total_actions += 1
                arole = action.get("role_arn", "")
                if arole and arole != pipeline_role:
                    has_scoped = True
        if total_actions:
            out.append(Finding(
                check_id="PBAC-005",
                title="CodePipeline stage action roles mirror the pipeline role",
                severity=Severity.HIGH,
                resource=p.address,
                description=(
                    "At least one stage action declares its own role_arn."
                    if has_scoped else
                    f"All {total_actions} actions inherit the pipeline-level role."
                ),
                recommendation="Assign per-action role_arn values.",
                passed=has_scoped,
            ))
        # CP-005 — production deploy stages need a preceding ManualApproval.
        missing: list[str] = []
        for idx, stage in enumerate(stages):
            s_name = (stage.get("name") or "").lower()
            actions = stage.get("action") or []
            action_names = [(a.get("name") or "").lower() for a in actions]
            is_prod = any(tok in s_name for tok in _PROD_TOKENS) or any(
                any(tok in an for tok in _PROD_TOKENS) for an in action_names
            )
            if not is_prod:
                continue
            prior_approval = any(
                a.get("category") == "Approval" and a.get("provider") == "Manual"
                for s in stages[:idx] for a in s.get("action") or []
            )
            stage_approval = any(
                a.get("category") == "Approval" and a.get("provider") == "Manual"
                for a in actions
            )
            if not (prior_approval or stage_approval):
                missing.append(stage.get("name") or f"stage[{idx}]")
        if missing:
            out.append(Finding(
                check_id="CP-005",
                title="Production Deploy stage has no preceding ManualApproval",
                severity=Severity.MEDIUM,
                resource=p.address,
                description=f"Production stage(s) {missing} have no preceding approval.",
                recommendation="Insert a Manual Approval action before production deploys.",
                passed=False,
            ))
        # CP-007 — V2 pipelines with unrestricted PR triggers.
        if p.values.get("pipeline_type") == "V2":
            open_triggers = []
            for idx, trig in enumerate(p.values.get("trigger") or []):
                if trig.get("provider_type") != "CodeStarSourceConnection":
                    continue
                git = trig.get("git_configuration") or {}
                if isinstance(git, list) and git:
                    git = git[0]
                pr_cfg = (git.get("pull_request") or [])
                for pr in pr_cfg:
                    branches = (pr.get("branches") or {})
                    if isinstance(branches, list) and branches:
                        branches = branches[0]
                    includes = branches.get("includes") or []
                    if not includes or "*" in includes:
                        open_triggers.append(f"trigger[{idx}]")
                        break
            if open_triggers:
                out.append(Finding(
                    check_id="CP-007",
                    title="CodePipeline v2 PR trigger accepts all branches",
                    severity=Severity.HIGH,
                    resource=p.address,
                    description=f"PR trigger(s) {open_triggers} accept any branch.",
                    recommendation="Add an includes filter under branches.",
                    passed=False,
                ))
    return out


def _eb001(ctx) -> list[Finding]:
    has_rule = False
    for r in ctx.resources("aws_cloudwatch_event_rule"):
        pattern = r.values.get("event_pattern")
        if not pattern:
            continue
        try:
            doc = json.loads(pattern) if isinstance(pattern, str) else pattern
        except (TypeError, json.JSONDecodeError):
            continue
        detail_types = doc.get("detail-type") or []
        if isinstance(detail_types, str):
            detail_types = [detail_types]
        if any("CodePipeline Pipeline Execution State Change" in dt for dt in detail_types):
            states = (doc.get("detail") or {}).get("state") or []
            if isinstance(states, str):
                states = [states]
            if "FAILED" in states:
                has_rule = True
                break
    # Only emit a finding if the plan declares ANY EventBridge rules —
    # plans that don't manage EventBridge at all shouldn't trip this.
    any_rules = any(True for _ in ctx.resources("aws_cloudwatch_event_rule"))
    if not any_rules:
        return []
    return [Finding(
        check_id="EB-001",
        title="No EventBridge rule for CodePipeline failure notifications",
        severity=Severity.MEDIUM,
        resource="plan-wide (aws_cloudwatch_event_rule)",
        description=(
            "At least one event rule matches CodePipeline FAILED state."
            if has_rule else
            "No aws_cloudwatch_event_rule matches CodePipeline FAILED state."
        ),
        recommendation=(
            "Add an aws_cloudwatch_event_rule with event_pattern matching "
            "CodePipeline Pipeline Execution State Change FAILED."
        ),
        passed=has_rule,
    )]
