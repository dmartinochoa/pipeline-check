"""Phase-3 Terraform parity: deeper detections that translate to HCL.

Runtime-only Phase-3 checks (Inspector v2 account status, Signer
profile revocation, CloudWatch alarm coverage, EventBridge target
ARNs) have no useful Terraform analogue and are omitted.
"""
from __future__ import annotations

import json
import re
from typing import Any

from ..base import Finding, Severity
from .base import TerraformBaseCheck, TerraformContext

_SG_REF_RE = re.compile(r"aws_security_group\.([A-Za-z0-9_-]+)")

_PR_EVENTS = {
    "PULL_REQUEST_CREATED", "PULL_REQUEST_UPDATED", "PULL_REQUEST_REOPENED",
}
_PROD_TOKENS = ("prod", "production", "live")
_ECR_TRUSTED_UPSTREAMS = {
    "public.ecr.aws", "registry.k8s.io", "ghcr.io", "gcr.io",
}
# A CodePipeline V2 branch include made up only of glob wildcards
# (``*``, ``**``, ``**/*``) matches every branch, exactly like the
# literal ``"*"`` the rule already treats as open.
_MATCH_ALL_GLOB_RE = re.compile(r"[*/]+")


def _is_match_all_glob(entry: object) -> bool:
    return isinstance(entry, str) and bool(_MATCH_ALL_GLOB_RE.fullmatch(entry.strip()))


class Phase3Checks(TerraformBaseCheck):

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(_ecr006(self.ctx))
        findings.extend(_pbac003(self.ctx))
        findings.extend(_pbac005_cp005_cp007(self.ctx))
        findings.extend(_eb001(self.ctx))
        return findings


def _ecr006(ctx: TerraformContext) -> list[Finding]:
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


def _codebuild_attached_sg_refs(
    ctx: TerraformContext,
) -> tuple[set[str], bool]:
    """Which security groups do CodeBuild projects attach, and is any
    CodeBuild project VPC-configured at all?

    Returns ``(referenced_sg_names, any_vpc_codebuild)``.
    ``referenced_sg_names`` are the ``aws_security_group`` resource names
    pulled from each project's ``vpc_config.security_group_ids`` (parsed
    out of interpolation strings when resolvable; empty when the ids are
    computed at plan time). ``any_vpc_codebuild`` gates the whole rule:
    with no VPC-configured CodeBuild project there is nothing PBAC-003 is
    meant to protect, so it must not fire on unrelated ALB/EC2/EKS SGs.
    """
    names: set[str] = set()
    any_vpc = False
    for cb in ctx.resources("aws_codebuild_project"):
        for vc in cb.values.get("vpc_config") or []:
            if not isinstance(vc, dict):
                continue
            any_vpc = True
            for sgid in vc.get("security_group_ids") or []:
                if isinstance(sgid, str):
                    names.update(_SG_REF_RE.findall(sgid))
    return names, any_vpc


def _pbac003(ctx: TerraformContext) -> list[Finding]:
    attached_names, any_vpc_codebuild = _codebuild_attached_sg_refs(ctx)
    if not any_vpc_codebuild:
        # No VPC-configured CodeBuild project in the plan — the rule is
        # CodeBuild-scoped (see title / docs_note), so an open-egress SG
        # on an ALB/EC2/EKS stack is not in scope.
        return []
    out: list[Finding] = []
    for sg in ctx.resources("aws_security_group"):
        # When the attached SG ids are resolvable, evaluate only those;
        # when they are computed at plan time (attached_names empty),
        # fall back to every SG so detection isn't silently lost.
        if attached_names and sg.name not in attached_names:
            continue
        for rule in sg.values.get("egress") or []:
            cidrs = rule.get("cidr_blocks") or []
            cidrs6 = rule.get("ipv6_cidr_blocks") or []
            proto = rule.get("protocol", "") or ""
            from_p = rule.get("from_port")
            to_p = rule.get("to_port")
            # An all-port egress to ``::/0`` is the same exposure as
            # ``0.0.0.0/0`` (the CloudFormation analog checks both).
            open_cidr = "0.0.0.0/0" in cidrs or "::/0" in cidrs6
            if open_cidr and (
                proto in ("-1", "all") or (from_p in (0, None) and to_p in (65535, None))
            ):
                dest = "0.0.0.0/0" if "0.0.0.0/0" in cidrs else "::/0"
                out.append(Finding(
                    check_id="PBAC-003",
                    title="Security group allows 0.0.0.0/0 all-port egress",
                    severity=Severity.MEDIUM,
                    resource=sg.address,
                    description=f"Egress rule allows {dest} on all ports.",
                    recommendation="Scope egress to specific destinations/ports.",
                    passed=False,
                ))
                break
    return out


def _action_role_arn_unknown(
    pipeline_unknown: dict[str, Any], s_idx: int, a_idx: int,
) -> bool:
    """Whether ``stage[s_idx].action[a_idx].role_arn`` is computed at
    apply time, per the pipeline's ``after_unknown`` tree.

    A ``role_arn = aws_iam_role.x.arn`` for a role created in the same
    plan is unknown; ``planned_values`` omits it, so it reads as absent.
    ``after_unknown`` distinguishes that from a genuinely role-less
    action. Navigated defensively: a ``True`` at any level means the
    whole subtree is unknown.
    """
    stages = pipeline_unknown.get("stage")
    if stages is True:
        return True
    if not isinstance(stages, list) or not 0 <= s_idx < len(stages):
        return False
    stage = stages[s_idx]
    if stage is True:
        return True
    if not isinstance(stage, dict):
        return False
    actions = stage.get("action")
    if actions is True:
        return True
    if not isinstance(actions, list) or not 0 <= a_idx < len(actions):
        return False
    action = actions[a_idx]
    if action is True:
        return True
    if not isinstance(action, dict):
        return False
    return action.get("role_arn") is True


def _pbac005_cp005_cp007(ctx: TerraformContext) -> list[Finding]:
    out: list[Finding] = []
    for p in ctx.resources("aws_codepipeline"):
        pipeline_role = p.values.get("role_arn", "")
        stages = p.values.get("stage") or []
        pipeline_unknown = ctx.after_unknown(p.address)
        # PBAC-005, any stage action with its own role_arn passes.
        has_scoped = False
        total_actions = 0
        for s_idx, stage in enumerate(stages):
            for a_idx, action in enumerate(stage.get("action") or []):
                total_actions += 1
                arole = action.get("role_arn", "")
                if arole and arole != pipeline_role:
                    has_scoped = True
                elif not arole and _action_role_arn_unknown(
                    pipeline_unknown, s_idx, a_idx,
                ):
                    # role_arn is a computed value (a per-action role
                    # created in the same plan), unresolved at plan time.
                    # The action DOES declare its own role, so it is
                    # scoped, not inheriting the pipeline role.
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
        # CP-005, production deploy stages need a preceding ManualApproval.
        missing: list[str] = []
        for idx, stage in enumerate(stages):
            s_name = (stage.get("name") or "").lower()
            actions = stage.get("action") or []
            action_names = [(a.get("name") or "").lower() for a in actions]
            is_prod = any(tok in s_name for tok in _PROD_TOKENS) or any(
                any(tok in an for tok in _PROD_TOKENS) for an in action_names
            )
            # The rule is about production *deploys*; a prod-named stage
            # that only runs tests (no Deploy action) is not a release
            # gate and must not be flagged for a missing approval.
            has_deploy = any(a.get("category") == "Deploy" for a in actions)
            if not (is_prod and has_deploy):
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
        # CP-007. V2 pipelines with unrestricted PR triggers.
        if p.values.get("pipeline_type") == "V2":
            open_triggers = []
            for idx, trig in enumerate(p.values.get("trigger") or []):
                if trig.get("provider_type") != "CodeStarSourceConnection":
                    continue
                git = trig.get("git_configuration") or {}
                if isinstance(git, list) and git:
                    git = git[0]
                pr_cfg = (git.get("pull_request") or []) if isinstance(git, dict) else []
                for pr in pr_cfg:
                    branches_raw = (pr.get("branches") or {}) if isinstance(pr, dict) else {}
                    if isinstance(branches_raw, list) and branches_raw:
                        branches_raw = branches_raw[0]
                    branches = branches_raw if isinstance(branches_raw, dict) else {}
                    includes = branches.get("includes") or []
                    if not includes or any(_is_match_all_glob(i) for i in includes):
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


def _eb001(ctx: TerraformContext) -> list[Finding]:
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
