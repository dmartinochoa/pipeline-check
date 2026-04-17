"""CloudFormation Phase-1 parity — CB-008..010, CT-*, CWL-*, SM-*, IAM-008.

Mirrors ``checks/terraform/extended.py``. IAM-007 (access-key age) is
runtime-only; the CFN parity rule drops back to nothing. CCM-001 has
no CFN analogue (CodeCommit approval-rule templates are CLI/SDK-only)
and is covered — where possible — in services.py.
"""
from __future__ import annotations

import json
import re

from .._iam_policy import (
    is_oidc_trust_stmt,
    iter_allow,
    oidc_audience_pinned,
    oidc_subject_pinned,
    public_principal,
)
from .._malicious import find_malicious_patterns
from ..base import Finding, Severity
from .base import CloudFormationBaseCheck, as_str, is_intrinsic, is_true

_DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}$")
_AWS_MANAGED_RE = re.compile(r"^aws/codebuild/")
_PR_EVENTS = {
    "PULL_REQUEST_CREATED",
    "PULL_REQUEST_UPDATED",
    "PULL_REQUEST_REOPENED",
}


class ExtendedChecks(CloudFormationBaseCheck):

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(_codebuild(self.ctx))
        findings.extend(_cloudtrail(self.ctx))
        findings.extend(_cw_logs(self.ctx))
        findings.extend(_secrets(self.ctx))
        findings.extend(_iam_oidc(self.ctx))
        return findings


def _codebuild(ctx) -> list[Finding]:
    out: list[Finding] = []
    for r in ctx.resources("AWS::CodeBuild::Project"):
        props = r.properties
        source = props.get("Source") or {}
        buildspec_raw = source.get("BuildSpec")
        buildspec = as_str(buildspec_raw).strip() if isinstance(buildspec_raw, str) else ""
        inline = False
        if isinstance(buildspec_raw, dict) and not is_intrinsic(buildspec_raw):
            # A mapping/scalar was inlined directly (rare but possible).
            inline = True
        elif buildspec:
            inline = (
                "\n" in buildspec
                or buildspec.startswith((
                    "version:", "phases:", "|", ">", "arn:aws:s3:::", "s3://",
                ))
            )
        out.append(Finding(
            check_id="CB-008",
            title="CodeBuild buildspec is inline (not sourced from a protected repo)",
            severity=Severity.HIGH,
            resource=r.address,
            description=(
                "Buildspec is inline or sourced from S3; any principal with "
                "cloudformation:UpdateStack can rewrite build commands without "
                "a source-repo review."
                if inline else
                "Buildspec is empty or references a repo-relative path."
            ),
            recommendation=(
                "Move buildspec.yml into the source repository under branch "
                "protection instead of inlining it in the template."
            ),
            passed=not inline,
        ))
        # CB-011 — scan the inline buildspec text for indicators of
        # malicious activity. Only meaningful when a buildspec string
        # is present; repo-sourced references have nothing to scan.
        if isinstance(buildspec_raw, str) and inline:
            hits = find_malicious_patterns(buildspec_raw.lower())
            if hits:
                categories = sorted({c for c, _n, _e in hits})
                summary = "; ".join(f"{n} ({e!r})" for _c, n, e in hits[:3])
                out.append(Finding(
                    check_id="CB-011",
                    title="CodeBuild buildspec contains indicators of malicious activity",
                    severity=Severity.CRITICAL,
                    resource=r.address,
                    description=(
                        f"Inline buildspec contains {len(hits)} indicator(s) "
                        f"of malicious activity ({', '.join(categories)}). "
                        f"Examples: {summary}{'...' if len(hits) > 3 else ''}."
                    ),
                    recommendation=(
                        "Treat as a potential pipeline compromise. Move the "
                        "buildspec out-of-line into a repo-sourced "
                        "``buildspec.yml`` under branch protection, rotate "
                        "any credentials the project's ServiceRole can reach, "
                        "and audit CloudTrail for outbound traffic."
                    ),
                    passed=False,
                ))
            else:
                out.append(Finding(
                    check_id="CB-011",
                    title="CodeBuild buildspec contains indicators of malicious activity",
                    severity=Severity.CRITICAL,
                    resource=r.address,
                    description="Inline buildspec has no detected indicators of malicious activity.",
                    recommendation="No action required.",
                    passed=True,
                ))
        else:
            out.append(Finding(
                check_id="CB-011",
                title="CodeBuild buildspec contains indicators of malicious activity",
                severity=Severity.CRITICAL,
                resource=r.address,
                description="Buildspec is repo-sourced or absent — no inline text to scan.",
                recommendation="No action required.",
                passed=True,
            ))
        env = props.get("Environment") or {}
        image = as_str(env.get("Image")).strip()
        if not image or _AWS_MANAGED_RE.match(image) or _DIGEST_RE.search(image):
            passed = True
            desc = "Image uses AWS-managed or digest-pinned source."
        else:
            passed = False
            desc = f"Image {image!r} is tag-pinned; registry tag moves get pulled on next build."
        out.append(Finding(
            check_id="CB-009",
            title="CodeBuild image not pinned by digest",
            severity=Severity.MEDIUM,
            resource=r.address,
            description=desc,
            recommendation="Pin custom images by ``@sha256:<digest>``.",
            passed=passed,
        ))
        triggers = props.get("Triggers") or {}
        if is_true(triggers.get("Webhook")):
            groups = triggers.get("FilterGroups") or []
            offenders: list[int] = []
            for idx, group in enumerate(groups):
                if not isinstance(group, list):
                    continue
                covers_pr = False
                has_actor = False
                for filt in group:
                    if not isinstance(filt, dict):
                        continue
                    f_type = as_str(filt.get("Type"))
                    pattern = as_str(filt.get("Pattern"))
                    if f_type == "EVENT":
                        events = {e.strip() for e in pattern.split(",") if e.strip()}
                        if events & _PR_EVENTS:
                            covers_pr = True
                    elif f_type == "ACTOR_ACCOUNT_ID":
                        has_actor = True
                if covers_pr and not has_actor:
                    offenders.append(idx)
            out.append(Finding(
                check_id="CB-010",
                title="CodeBuild webhook allows fork-PR builds without actor filtering",
                severity=Severity.HIGH,
                resource=r.address,
                description=(
                    f"FilterGroup(s) {offenders} build PRs but have no "
                    "ACTOR_ACCOUNT_ID filter — any fork can trigger a build."
                    if offenders else
                    "Webhook either does not build PRs or pins ACTOR_ACCOUNT_ID."
                ),
                recommendation=(
                    "Add an ACTOR_ACCOUNT_ID filter to every PR-triggering "
                    "FilterGroup or remove the PULL_REQUEST_* events."
                ),
                passed=not offenders,
            ))
    return out


def _cloudtrail(ctx) -> list[Finding]:
    out: list[Finding] = []
    trails = list(ctx.resources("AWS::CloudTrail::Trail"))
    if not trails:
        out.append(Finding(
            check_id="CT-001",
            title="No CloudTrail trail defined in the template",
            severity=Severity.HIGH,
            resource="AWS::CloudTrail::Trail (template-wide)",
            description=(
                "The template declares no AWS::CloudTrail::Trail. Unless a "
                "trail exists out-of-band, management-plane activity has no "
                "durable audit record."
            ),
            recommendation=(
                "Declare an AWS::CloudTrail::Trail resource or confirm one exists externally."
            ),
            passed=False,
        ))
    else:
        out.append(Finding(
            check_id="CT-001",
            title="CloudTrail trail defined in the template",
            severity=Severity.HIGH,
            resource=", ".join(t.address for t in trails),
            description=f"Template defines {len(trails)} CloudTrail trail(s).",
            recommendation="No action required.",
            passed=True,
        ))
    for t in trails:
        validation = is_true(t.properties.get("EnableLogFileValidation"))
        out.append(Finding(
            check_id="CT-002",
            title="CloudTrail log-file validation disabled",
            severity=Severity.MEDIUM,
            resource=t.address,
            description=(
                "EnableLogFileValidation: true."
                if validation else
                "EnableLogFileValidation is false/unset; tampering in S3 cannot be detected."
            ),
            recommendation="Set EnableLogFileValidation: true.",
            passed=validation,
        ))
        multi = is_true(t.properties.get("IsMultiRegionTrail"))
        out.append(Finding(
            check_id="CT-003",
            title="CloudTrail trail is not multi-region",
            severity=Severity.MEDIUM,
            resource=t.address,
            description=(
                "IsMultiRegionTrail: true."
                if multi else
                "IsMultiRegionTrail is false/unset; activity in other regions is not captured."
            ),
            recommendation="Set IsMultiRegionTrail: true.",
            passed=multi,
        ))
    return out


def _cw_logs(ctx) -> list[Finding]:
    out: list[Finding] = []
    for r in ctx.resources("AWS::Logs::LogGroup"):
        name = as_str(r.properties.get("LogGroupName"))
        if not name.startswith("/aws/codebuild/"):
            continue
        retention = r.properties.get("RetentionInDays")
        has_retention = isinstance(retention, (int, float)) and retention > 0
        out.append(Finding(
            check_id="CWL-001",
            title="CodeBuild log group has no retention policy",
            severity=Severity.LOW,
            resource=r.address,
            description=(
                f"RetentionInDays: {retention}." if has_retention
                else "RetentionInDays is unset; logs retained forever."
            ),
            recommendation="Set RetentionInDays to a finite value.",
            passed=has_retention,
        ))
        kms = r.properties.get("KmsKeyId")
        has_kms = bool(kms)
        out.append(Finding(
            check_id="CWL-002",
            title="CodeBuild log group not KMS-encrypted",
            severity=Severity.MEDIUM,
            resource=r.address,
            description=(
                f"KmsKeyId: {kms}." if has_kms
                else "KmsKeyId is unset; logs use AWS-owned encryption."
            ),
            recommendation="Set KmsKeyId to a customer-managed KMS key ARN.",
            passed=has_kms,
        ))
    return out


def _secrets(ctx) -> list[Finding]:
    out: list[Finding] = []
    # SM-001 — rotations referenced by SecretId or by !Ref LogicalId.
    rotation_targets: set[str] = set()
    for r in ctx.resources("AWS::SecretsManager::RotationSchedule"):
        target = r.properties.get("SecretId")
        if isinstance(target, str):
            rotation_targets.add(target)
        elif isinstance(target, dict) and "Ref" in target:
            rotation_targets.add(f"ref:{target['Ref']}")
    for secret in ctx.resources("AWS::SecretsManager::Secret"):
        name = as_str(secret.properties.get("Name")) or secret.logical_id
        has_rot = (
            name in rotation_targets
            or f"ref:{secret.logical_id}" in rotation_targets
        )
        out.append(Finding(
            check_id="SM-001",
            title="Secrets Manager secret has no rotation configured",
            severity=Severity.HIGH,
            resource=secret.address,
            description=(
                "Matching AWS::SecretsManager::RotationSchedule found."
                if has_rot else
                "No RotationSchedule resource references this secret."
            ),
            recommendation="Declare a RotationSchedule for this secret.",
            passed=has_rot,
        ))
    # SM-002 — resource policies grant wildcard principal?
    for policy in ctx.resources("AWS::SecretsManager::ResourcePolicy"):
        doc = _parse_policy(policy.properties.get("ResourcePolicy"))
        offenders = [i for i, s in enumerate(iter_allow(doc)) if public_principal(s)]
        out.append(Finding(
            check_id="SM-002",
            title="Secrets Manager resource policy allows wildcard principal",
            severity=Severity.CRITICAL,
            resource=policy.address,
            description=(
                f"Allow statement(s) {offenders} grant Principal: '*'." if offenders
                else "No wildcard-principal Allow statements."
            ),
            recommendation=(
                "Remove ``Principal: '*'`` or add an aws:PrincipalOrgID condition."
            ),
            passed=not offenders,
        ))
    return out


def _iam_oidc(ctx) -> list[Finding]:
    out: list[Finding] = []
    for role in ctx.resources("AWS::IAM::Role"):
        doc = role.properties.get("AssumeRolePolicyDocument")
        if not isinstance(doc, dict):
            continue
        stmts = doc.get("Statement") or []
        if isinstance(stmts, dict):
            stmts = [stmts]
        offending: list[str] = []
        matched = False
        for idx, stmt in enumerate(stmts):
            if not isinstance(stmt, dict):
                continue
            host = is_oidc_trust_stmt(stmt)
            if not host:
                continue
            matched = True
            if not oidc_audience_pinned(stmt):
                offending.append(f"stmt[{idx}]({host}): missing :aud condition")
            elif not oidc_subject_pinned(stmt):
                offending.append(f"stmt[{idx}]({host}): missing :sub condition")
        if not matched:
            continue
        out.append(Finding(
            check_id="IAM-008",
            title="OIDC-federated role trust policy missing audience or subject pin",
            severity=Severity.HIGH,
            resource=role.address,
            description=(
                "OIDC trust pins both audience and subject." if not offending
                else f"OIDC trust under-scoped: {'; '.join(offending)}."
            ),
            recommendation=(
                "Pin both ``...:aud`` and ``...:sub`` conditions on every "
                "federated trust statement; wildcard subjects are insufficient."
            ),
            passed=not offending,
        ))
    return out


def _parse_policy(raw):
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}
    return {}
