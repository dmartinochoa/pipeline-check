"""CloudFormation Phase-3 parity — ECR-006, PBAC-003/005, CP-005/007, EB-001.

Mirrors ``checks/terraform/phase3.py``. Runtime-only Phase-3 checks
(ECR-007 Inspector state, SIGN-001/002 profile status, EB-002 wildcard
targets, CW-001 alarm coverage) have no useful CFN analogue and are
omitted.
"""
from __future__ import annotations

import json

from ..base import Finding, Severity
from .base import CloudFormationBaseCheck, as_str

_PR_EVENTS = {
    "PULL_REQUEST_CREATED", "PULL_REQUEST_UPDATED", "PULL_REQUEST_REOPENED",
}
_PROD_TOKENS = ("prod", "production", "live")
_ECR_TRUSTED_UPSTREAMS = {
    "public.ecr.aws", "registry.k8s.io", "ghcr.io", "gcr.io",
}


class Phase3Checks(CloudFormationBaseCheck):

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(_ecr006(self.ctx))
        findings.extend(_pbac003(self.ctx))
        findings.extend(_pbac005_cp005_cp007(self.ctx))
        findings.extend(_eb001(self.ctx))
        return findings


def _ecr006(ctx) -> list[Finding]:
    out: list[Finding] = []
    for r in ctx.resources("AWS::ECR::PullThroughCacheRule"):
        upstream = as_str(r.properties.get("UpstreamRegistryUrl"))
        has_cred = bool(r.properties.get("CredentialArn"))
        passed = upstream in _ECR_TRUSTED_UPSTREAMS or has_cred
        out.append(Finding(
            check_id="ECR-006",
            title="ECR pull-through cache rule uses an untrusted upstream",
            severity=Severity.HIGH,
            resource=r.address,
            description=(
                f"Upstream {upstream} is trusted or authenticated." if passed
                else f"Upstream {upstream!r} is unauthenticated and not on the trusted allow-list."
            ),
            recommendation="Scope upstreams to trusted registries or add CredentialArn.",
            passed=passed,
        ))
    return out


def _pbac003(ctx) -> list[Finding]:
    out: list[Finding] = []
    for sg in ctx.resources("AWS::EC2::SecurityGroup"):
        for rule in sg.properties.get("SecurityGroupEgress") or []:
            if not isinstance(rule, dict):
                continue
            cidr = as_str(rule.get("CidrIp"))
            proto = as_str(rule.get("IpProtocol"))
            from_p = rule.get("FromPort")
            to_p = rule.get("ToPort")
            if cidr == "0.0.0.0/0" and (
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
    for p in ctx.resources("AWS::CodePipeline::Pipeline"):
        pipeline_role = _canon(p.properties.get("RoleArn"))
        stages = p.properties.get("Stages") or []

        # PBAC-005
        has_scoped = False
        total_actions = 0
        for stage in stages:
            if not isinstance(stage, dict):
                continue
            for action in stage.get("Actions") or []:
                if not isinstance(action, dict):
                    continue
                total_actions += 1
                arole = _canon(action.get("RoleArn"))
                if arole and arole != pipeline_role:
                    has_scoped = True
        if total_actions:
            out.append(Finding(
                check_id="PBAC-005",
                title="CodePipeline stage action roles mirror the pipeline role",
                severity=Severity.HIGH,
                resource=p.address,
                description=(
                    "At least one stage action declares its own RoleArn."
                    if has_scoped else
                    f"All {total_actions} actions inherit the pipeline-level role."
                ),
                recommendation="Assign per-action RoleArn values.",
                passed=has_scoped,
            ))

        # CP-005
        missing: list[str] = []
        for idx, stage in enumerate(stages):
            if not isinstance(stage, dict):
                continue
            s_name = as_str(stage.get("Name")).lower()
            actions = stage.get("Actions") or []
            action_names = [as_str(a.get("Name")).lower() for a in actions if isinstance(a, dict)]
            is_prod = (
                any(tok in s_name for tok in _PROD_TOKENS)
                or any(any(tok in an for tok in _PROD_TOKENS) for an in action_names)
            )
            if not is_prod:
                continue
            prior_approval = False
            for earlier in stages[:idx]:
                if not isinstance(earlier, dict):
                    continue
                for a in earlier.get("Actions") or []:
                    if not isinstance(a, dict):
                        continue
                    type_id = a.get("ActionTypeId") or {}
                    if (
                        as_str(type_id.get("Category")) == "Approval"
                        and as_str(type_id.get("Provider")) == "Manual"
                    ):
                        prior_approval = True
                        break
                if prior_approval:
                    break
            stage_approval = any(
                isinstance(a, dict)
                and as_str((a.get("ActionTypeId") or {}).get("Category")) == "Approval"
                and as_str((a.get("ActionTypeId") or {}).get("Provider")) == "Manual"
                for a in actions
            )
            if not (prior_approval or stage_approval):
                missing.append(as_str(stage.get("Name")) or f"stage[{idx}]")
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

        # CP-007 — V2 PipelineType with unrestricted PR trigger
        if as_str(p.properties.get("PipelineType")) == "V2":
            open_triggers = []
            triggers = p.properties.get("Triggers") or []
            for idx, trig in enumerate(triggers):
                if not isinstance(trig, dict):
                    continue
                if as_str(trig.get("ProviderType")) != "CodeStarSourceConnection":
                    continue
                git = trig.get("GitConfiguration") or {}
                pr_cfg = git.get("PullRequest") or []
                for pr in pr_cfg:
                    if not isinstance(pr, dict):
                        continue
                    branches = pr.get("Branches") or {}
                    includes = branches.get("Includes") or []
                    if not includes or "*" in includes:
                        open_triggers.append(f"Triggers[{idx}]")
                        break
            if open_triggers:
                out.append(Finding(
                    check_id="CP-007",
                    title="CodePipeline v2 PR trigger accepts all branches",
                    severity=Severity.HIGH,
                    resource=p.address,
                    description=f"PR trigger(s) {open_triggers} accept any branch.",
                    recommendation="Add an Includes filter under Branches.",
                    passed=False,
                ))
    return out


def _eb001(ctx) -> list[Finding]:
    rules = list(ctx.resources("AWS::Events::Rule"))
    if not rules:
        return []
    has_rule = False
    for r in rules:
        pattern = r.properties.get("EventPattern")
        if isinstance(pattern, str):
            try:
                doc = json.loads(pattern)
            except json.JSONDecodeError:
                continue
        elif isinstance(pattern, dict):
            doc = pattern
        else:
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
    return [Finding(
        check_id="EB-001",
        title="No EventBridge rule for CodePipeline failure notifications",
        severity=Severity.MEDIUM,
        resource="template-wide (AWS::Events::Rule)",
        description=(
            "At least one event rule matches CodePipeline FAILED state."
            if has_rule else
            "No AWS::Events::Rule matches CodePipeline FAILED state."
        ),
        recommendation=(
            "Add an AWS::Events::Rule whose EventPattern matches "
            "'CodePipeline Pipeline Execution State Change' with state FAILED."
        ),
        passed=has_rule,
    )]


def _canon(role_value) -> str:
    """Canonicalise a RoleArn value so intrinsic refs compare equal."""
    if isinstance(role_value, str):
        return role_value
    if isinstance(role_value, dict):
        if "Ref" in role_value:
            return f"ref:{role_value['Ref']}"
        if "Fn::GetAtt" in role_value:
            att = role_value["Fn::GetAtt"]
            if isinstance(att, list) and att:
                return f"ref:{att[0]}"
    return ""
