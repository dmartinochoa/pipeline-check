"""Phase-1 Terraform parity checks.

Mirrors the runtime AWS rules under
``pipeline_check/core/checks/aws/rules/`` for shift-left (pre-apply)
scanning. IAM-007 (access-key age) has no Terraform analogue — key
rotation state only exists at runtime.

CB-008   Buildspec declared inline, not sourced from repo       HIGH    CICD-SEC-4
CB-009   CodeBuild image not pinned by sha256 digest            MEDIUM  CICD-SEC-3
CB-010   Webhook allows fork PR builds without actor filter     HIGH    CICD-SEC-4
CT-001   No aws_cloudtrail resource in the plan                 HIGH    CICD-SEC-10
CT-002   aws_cloudtrail.enable_log_file_validation = false      MEDIUM  CICD-SEC-10
CT-003   aws_cloudtrail.is_multi_region_trail = false           MEDIUM  CICD-SEC-10
CWL-001  aws_cloudwatch_log_group has no retention_in_days      LOW     CICD-SEC-10
CWL-002  aws_cloudwatch_log_group has no kms_key_id             MEDIUM  CICD-SEC-9
SM-001   aws_secretsmanager_secret has no matching rotation res HIGH    CICD-SEC-6
SM-002   secret resource policy grants Principal: "*"           CRIT    CICD-SEC-8
IAM-008  OIDC-federated role missing audience/subject pin       HIGH    CICD-SEC-2
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
from .base import TerraformBaseCheck

_DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}$")
_AWS_MANAGED_RE = re.compile(r"^aws/codebuild/")
_PR_EVENTS = {
    "PULL_REQUEST_CREATED",
    "PULL_REQUEST_UPDATED",
    "PULL_REQUEST_REOPENED",
}


def _first(block_list):
    if not block_list:
        return {}
    return block_list[0] or {}


class ExtendedChecks(TerraformBaseCheck):
    """Runs every Phase-1 extended rule against the Terraform plan."""

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(_codebuild_checks(self.ctx))
        findings.extend(_cloudtrail_checks(self.ctx))
        findings.extend(_cw_logs_checks(self.ctx))
        findings.extend(_secretsmanager_checks(self.ctx))
        findings.extend(_iam_oidc_check(self.ctx))
        return findings


# ---------------------------------------------------------------------------
# CodeBuild
# ---------------------------------------------------------------------------

def _codebuild_checks(ctx) -> list[Finding]:
    projects = list(ctx.resources("aws_codebuild_project"))
    webhooks = {
        w.values.get("project_name", ""): w.values
        for w in ctx.resources("aws_codebuild_webhook")
    }
    out: list[Finding] = []
    for r in projects:
        name = r.values.get("name") or r.name
        out.append(_cb008(r.values, r.address))
        out.append(_cb009(r.values, r.address))
        out.append(_cb011(r.values, r.address))
        hook = webhooks.get(name)
        if hook is not None:
            out.append(_cb010(hook, r.address))
    return out


def _cb011(values: dict, address: str) -> Finding:
    """CB-011 — inline buildspec has indicators of malicious activity."""
    source = _first(values.get("source"))
    buildspec = (source.get("buildspec") or "").strip()
    # Skip repo-referenced buildspecs — the text isn't visible in the plan.
    if (
        not buildspec
        or (
            "\n" not in buildspec
            and not buildspec.startswith(("version:", "phases:"))
        )
    ):
        return Finding(
            check_id="CB-011",
            title="CodeBuild buildspec contains indicators of malicious activity",
            severity=Severity.CRITICAL,
            resource=address,
            description="Buildspec is repo-sourced or absent — no inline text to scan.",
            recommendation="No action required.",
            passed=True,
        )
    hits = find_malicious_patterns(buildspec.lower())
    if not hits:
        return Finding(
            check_id="CB-011",
            title="CodeBuild buildspec contains indicators of malicious activity",
            severity=Severity.CRITICAL,
            resource=address,
            description="Inline buildspec has no detected indicators of malicious activity.",
            recommendation="No action required.",
            passed=True,
        )
    categories = sorted({c for c, _n, _e in hits})
    summary = "; ".join(f"{n} ({e!r})" for _c, n, e in hits[:3])
    return Finding(
        check_id="CB-011",
        title="CodeBuild buildspec contains indicators of malicious activity",
        severity=Severity.CRITICAL,
        resource=address,
        description=(
            f"Inline buildspec contains {len(hits)} indicator(s) of "
            f"malicious activity ({', '.join(categories)}). Examples: "
            f"{summary}{'...' if len(hits) > 3 else ''}."
        ),
        recommendation=(
            "Treat as a potential pipeline compromise. Identify the "
            "commit that introduced this buildspec, rotate any "
            "credentials the project's ServiceRole can reach, and "
            "move the buildspec out-of-line into a repo-sourced "
            "``buildspec.yml`` under branch protection."
        ),
        passed=False,
    )


def _cb008(values: dict, address: str) -> Finding:
    source = _first(values.get("source"))
    buildspec = (source.get("buildspec") or "").strip()
    inline = (
        bool(buildspec)
        and (
            "\n" in buildspec
            or buildspec.startswith(("version:", "phases:", "|", ">", "arn:aws:s3:::", "s3://"))
        )
    )
    return Finding(
        check_id="CB-008",
        title="CodeBuild buildspec is inline (not sourced from a protected repo)",
        severity=Severity.HIGH,
        resource=address,
        description=(
            "Buildspec is declared inline or sourced from S3; any principal "
            "with codebuild:UpdateProject can rewrite build commands without "
            "a source-repo review."
            if inline else
            "Buildspec is empty or sourced from the repository."
        ),
        recommendation=(
            "Move buildspec.yml into the source repository under branch "
            "protection instead of declaring it inline."
        ),
        passed=not inline,
    )


def _cb009(values: dict, address: str) -> Finding:
    env = _first(values.get("environment"))
    image = (env.get("image") or "").strip()
    if not image or _AWS_MANAGED_RE.match(image) or _DIGEST_RE.search(image):
        passed = True
        desc = "Image uses AWS-managed or digest-pinned source."
    else:
        passed = False
        desc = f"Image {image!r} is tag-pinned; a tag move would be pulled on next build."
    return Finding(
        check_id="CB-009",
        title="CodeBuild image not pinned by digest",
        severity=Severity.MEDIUM,
        resource=address,
        description=desc,
        recommendation="Pin custom images by ``@sha256:<digest>``.",
        passed=passed,
    )


def _cb010(webhook: dict, address: str) -> Finding:
    groups = webhook.get("filter_group") or []
    offenders: list[int] = []
    for idx, group in enumerate(groups):
        filters = group.get("filter") or []
        covers_pr = False
        has_actor = False
        for filt in filters:
            f_type = filt.get("type")
            pattern = filt.get("pattern", "") or ""
            if f_type == "EVENT":
                events = {e.strip() for e in pattern.split(",") if e.strip()}
                if events & _PR_EVENTS:
                    covers_pr = True
            elif f_type == "ACTOR_ACCOUNT_ID":
                has_actor = True
        if covers_pr and not has_actor:
            offenders.append(idx)
    passed = not offenders
    return Finding(
        check_id="CB-010",
        title="CodeBuild webhook allows fork-PR builds without actor filtering",
        severity=Severity.HIGH,
        resource=address,
        description=(
            f"Filter group(s) {offenders} build PRs but have no "
            "ACTOR_ACCOUNT_ID filter — any fork can trigger a build."
            if offenders else
            "Webhook either does not build PRs or pins ACTOR_ACCOUNT_ID."
        ),
        recommendation=(
            "Add an ACTOR_ACCOUNT_ID filter to every PR-triggering group "
            "or remove the PULL_REQUEST_* events."
        ),
        passed=passed,
    )


# ---------------------------------------------------------------------------
# CloudTrail
# ---------------------------------------------------------------------------

def _cloudtrail_checks(ctx) -> list[Finding]:
    trails = list(ctx.resources("aws_cloudtrail"))
    out: list[Finding] = []
    if not trails:
        out.append(Finding(
            check_id="CT-001",
            title="No CloudTrail trail defined in the plan",
            severity=Severity.HIGH,
            resource="aws_cloudtrail (plan-wide)",
            description=(
                "The Terraform plan declares no aws_cloudtrail resource. "
                "Unless a trail exists out-of-band, management-plane activity "
                "has no durable audit record."
            ),
            recommendation="Declare an aws_cloudtrail resource or confirm one exists externally.",
            passed=False,
        ))
    else:
        out.append(Finding(
            check_id="CT-001",
            title="CloudTrail trail defined in the plan",
            severity=Severity.HIGH,
            resource=", ".join(t.address for t in trails),
            description=f"Plan defines {len(trails)} CloudTrail trail(s).",
            recommendation="No action required.",
            passed=True,
        ))
    for t in trails:
        validation = bool(t.values.get("enable_log_file_validation"))
        out.append(Finding(
            check_id="CT-002",
            title="CloudTrail log-file validation disabled",
            severity=Severity.MEDIUM,
            resource=t.address,
            description=(
                "enable_log_file_validation = true."
                if validation else
                "enable_log_file_validation is false; tampering in S3 cannot be detected."
            ),
            recommendation="Set enable_log_file_validation = true.",
            passed=validation,
        ))
        multi = bool(t.values.get("is_multi_region_trail"))
        out.append(Finding(
            check_id="CT-003",
            title="CloudTrail trail is not multi-region",
            severity=Severity.MEDIUM,
            resource=t.address,
            description=(
                "is_multi_region_trail = true."
                if multi else
                "is_multi_region_trail is false; activity in other regions is not captured."
            ),
            recommendation="Set is_multi_region_trail = true.",
            passed=multi,
        ))
    return out


# ---------------------------------------------------------------------------
# CloudWatch Logs
# ---------------------------------------------------------------------------

def _cw_logs_checks(ctx) -> list[Finding]:
    out: list[Finding] = []
    for r in ctx.resources("aws_cloudwatch_log_group"):
        name = r.values.get("name", "") or ""
        if not name.startswith("/aws/codebuild/"):
            continue
        retention = r.values.get("retention_in_days")
        out.append(Finding(
            check_id="CWL-001",
            title="CodeBuild log group has no retention policy",
            severity=Severity.LOW,
            resource=r.address,
            description=(
                f"retention_in_days = {retention}."
                if retention else
                "retention_in_days is unset; logs are retained forever."
            ),
            recommendation="Set retention_in_days to a finite value.",
            passed=bool(retention),
        ))
        kms = r.values.get("kms_key_id")
        out.append(Finding(
            check_id="CWL-002",
            title="CodeBuild log group not KMS-encrypted",
            severity=Severity.MEDIUM,
            resource=r.address,
            description=(
                f"kms_key_id = {kms}."
                if kms else
                "kms_key_id is unset; logs use AWS-owned encryption."
            ),
            recommendation="Set kms_key_id to a customer-managed CMK ARN.",
            passed=bool(kms),
        ))
    return out


# ---------------------------------------------------------------------------
# Secrets Manager
# ---------------------------------------------------------------------------

def _secretsmanager_checks(ctx) -> list[Finding]:
    rotations = {
        r.values.get("secret_id", ""): r.values
        for r in ctx.resources("aws_secretsmanager_secret_rotation")
    }
    out: list[Finding] = []
    for secret in ctx.resources("aws_secretsmanager_secret"):
        name = secret.values.get("name") or secret.name
        has_rot = any(
            sid == name or sid == secret.values.get("arn") or sid == f"${{aws_secretsmanager_secret.{secret.name}.id}}"
            for sid in rotations
        )
        out.append(Finding(
            check_id="SM-001",
            title="Secrets Manager secret has no rotation configured",
            severity=Severity.HIGH,
            resource=secret.address,
            description=(
                "Matching aws_secretsmanager_secret_rotation found."
                if has_rot else
                "No aws_secretsmanager_secret_rotation references this secret."
            ),
            recommendation="Declare an aws_secretsmanager_secret_rotation for this secret.",
            passed=has_rot,
        ))
    for policy in ctx.resources("aws_secretsmanager_secret_policy"):
        raw = policy.values.get("policy")
        doc = _parse_policy(raw)
        offenders = [
            idx for idx, stmt in enumerate(iter_allow(doc))
            if public_principal(stmt)
        ]
        out.append(Finding(
            check_id="SM-002",
            title="Secrets Manager resource policy allows wildcard principal",
            severity=Severity.CRITICAL,
            resource=policy.address,
            description=(
                f"Allow statement(s) {offenders} grant Principal: '*'."
                if offenders else
                "No wildcard-principal Allow statements."
            ),
            recommendation=(
                "Remove ``Principal: '*'`` from Allow statements or scope "
                "them with an aws:PrincipalOrgID condition."
            ),
            passed=not offenders,
        ))
    return out


# ---------------------------------------------------------------------------
# IAM — OIDC
# ---------------------------------------------------------------------------

def _iam_oidc_check(ctx) -> list[Finding]:
    out: list[Finding] = []
    for role in ctx.resources("aws_iam_role"):
        doc = _parse_policy(role.values.get("assume_role_policy"))
        stmts = doc.get("Statement", [])
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
                "OIDC trust pins both audience and subject."
                if not offending else
                f"OIDC trust under-scoped: {'; '.join(offending)}."
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
