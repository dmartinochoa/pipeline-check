"""Phase-2 Terraform parity: CodeArtifact, CodeCommit, Lambda, KMS, SSM.

Mirrors the AWS runtime rules under ``aws/rules/`` for shift-left scans.
Some runtime checks don't translate (e.g. KMS-001 needs "is rotation
actually on?" which is a runtime query — the Terraform analogue is
``enable_key_rotation`` on ``aws_kms_key``).
"""
from __future__ import annotations

import json

from .._iam_policy import as_list, iter_allow, public_principal
from .._patterns import SECRET_NAME_RE, SECRET_VALUE_RE
from ..base import Finding, Severity
from .base import TerraformBaseCheck


def _parse_policy(raw):
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}
    return {}


class ServiceChecks(TerraformBaseCheck):
    """Runs every Phase-2 service rule against the plan."""

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(_codeartifact(self.ctx))
        findings.extend(_codecommit(self.ctx))
        findings.extend(_lambda(self.ctx))
        findings.extend(_kms(self.ctx))
        findings.extend(_ssm(self.ctx))
        return findings


# ---------------------------------------------------------------------------
# CodeArtifact
# ---------------------------------------------------------------------------

def _codeartifact(ctx) -> list[Finding]:
    out: list[Finding] = []
    for d in ctx.resources("aws_codeartifact_domain"):
        key = d.values.get("encryption_key", "") or ""
        passed = bool(key) and "alias/aws/" not in key
        out.append(Finding(
            check_id="CA-001",
            title="CodeArtifact domain not encrypted with customer KMS CMK",
            severity=Severity.MEDIUM,
            resource=d.address,
            description=(
                f"encryption_key = {key}." if passed
                else "encryption_key not set; domain will use the AWS-owned key."
            ),
            recommendation="Set encryption_key to a CMK ARN at creation.",
            passed=passed,
        ))
    for r in ctx.resources("aws_codeartifact_repository"):
        conns = r.values.get("external_connections") or []
        public = [c for c in conns if isinstance(c, str) and c.startswith("public:")]
        out.append(Finding(
            check_id="CA-002",
            title="CodeArtifact repository has a public external connection",
            severity=Severity.HIGH,
            resource=r.address,
            description=(
                f"Public external_connections: {public}." if public
                else "No public external_connections declared."
            ),
            recommendation="Route public consumption through a pull-through cache with an allow-list.",
            passed=not public,
        ))
    for p in ctx.resources("aws_codeartifact_domain_permissions_policy"):
        doc = _parse_policy(p.values.get("policy_document"))
        offenders = [i for i, s in enumerate(iter_allow(doc)) if public_principal(s)]
        out.append(Finding(
            check_id="CA-003",
            title="CodeArtifact domain policy allows cross-account wildcard",
            severity=Severity.CRITICAL,
            resource=p.address,
            description=(
                f"Allow statement(s) {offenders} grant Principal: '*'." if offenders
                else "No wildcard-principal Allow statements."
            ),
            recommendation="Remove ``Principal: '*'`` or add an aws:PrincipalOrgID condition.",
            passed=not offenders,
        ))
    for p in ctx.resources("aws_codeartifact_repository_permissions_policy"):
        doc = _parse_policy(p.values.get("policy_document"))
        over_broad = False
        for stmt in iter_allow(doc):
            actions = as_list(stmt.get("Action"))
            resources = as_list(stmt.get("Resource"))
            if (
                any(a in ("*", "codeartifact:*") for a in actions if isinstance(a, str))
                and (not resources or "*" in resources)
            ):
                over_broad = True
                break
        out.append(Finding(
            check_id="CA-004",
            title="CodeArtifact repo policy grants codeartifact:* with Resource '*'",
            severity=Severity.HIGH,
            resource=p.address,
            description=(
                "Policy grants codeartifact:* with Resource '*'." if over_broad
                else "Actions and resources are scoped."
            ),
            recommendation="Scope actions and resources on every Allow statement.",
            passed=not over_broad,
        ))
    return out


# ---------------------------------------------------------------------------
# CodeCommit
# ---------------------------------------------------------------------------

def _codecommit(ctx) -> list[Finding]:
    out: list[Finding] = []
    approvals = {
        a.values.get("repository_name", "")
        for a in ctx.resources("aws_codecommit_approval_rule_template_association")
    }
    for r in ctx.resources("aws_codecommit_repository"):
        name = r.values.get("repository_name") or r.name
        has_template = name in approvals
        out.append(Finding(
            check_id="CCM-001",
            title="CodeCommit repository has no approval rule template attached",
            severity=Severity.HIGH,
            resource=r.address,
            description=(
                "Approval-rule template association found." if has_template
                else "No aws_codecommit_approval_rule_template_association references this repo."
            ),
            recommendation="Attach an approval rule template to require reviewer approval.",
            passed=has_template,
        ))
        key = r.values.get("kms_key_id", "") or ""
        passed = bool(key) and "alias/aws/codecommit" not in key
        out.append(Finding(
            check_id="CCM-002",
            title="CodeCommit repository not encrypted with customer KMS CMK",
            severity=Severity.MEDIUM,
            resource=r.address,
            description=(
                f"kms_key_id = {key}." if passed else
                "kms_key_id unset or AWS-owned; repository uses default encryption."
            ),
            recommendation="Set kms_key_id to a CMK ARN.",
            passed=passed,
        ))
    # CCM-003 cross-account triggers — static check compares trigger dest
    # account against every aws_codecommit_trigger in the plan.
    for t in ctx.resources("aws_codecommit_trigger"):
        triggers = t.values.get("trigger") or []
        offenders = []
        for trig in triggers:
            dest = (trig.get("destination_arn") or "").strip()
            # If the ARN includes an account id that appears elsewhere in the
            # plan's declared resources with a matching type, treat as same-account.
            # Without an AWS account context in the plan, we flag any trigger
            # whose destination is not a reference/interpolation — a literal
            # ARN is suspicious and worth a manual review.
            if dest and dest.count(":") >= 4 and "${" not in dest:
                offenders.append(dest)
        out.append(Finding(
            check_id="CCM-003",
            title="CodeCommit trigger targets SNS/Lambda in a different account",
            severity=Severity.MEDIUM,
            resource=t.address,
            description=(
                f"Literal destination_arn(s) ({offenders}) — verify these "
                "stay within the repository's account."
                if offenders else
                "All destinations are plan-resource references."
            ),
            recommendation=(
                "Reference trigger destinations via Terraform resource "
                "attributes instead of literal cross-account ARNs."
            ),
            passed=not offenders,
        ))
    return out


# ---------------------------------------------------------------------------
# Lambda
# ---------------------------------------------------------------------------

def _lambda(ctx) -> list[Finding]:
    out: list[Finding] = []
    url_by_fn = {
        (u.values.get("function_name") or ""): u.values
        for u in ctx.resources("aws_lambda_function_url")
    }
    for fn in ctx.resources("aws_lambda_function"):
        name = fn.values.get("function_name") or fn.name
        signing = fn.values.get("code_signing_config_arn")
        out.append(Finding(
            check_id="LMB-001",
            title="Lambda function has no code-signing config",
            severity=Severity.HIGH,
            resource=fn.address,
            description=(
                f"code_signing_config_arn = {signing}." if signing else
                "code_signing_config_arn is unset; unsigned code is deployable."
            ),
            recommendation="Set code_signing_config_arn on every function that deploys release artifacts.",
            passed=bool(signing),
        ))
        env_vars = (_first_map(fn.values.get("environment"))).get("variables", {}) or {}
        suspicious = [k for k in env_vars if isinstance(k, str) and SECRET_NAME_RE.search(k)]
        suspicious += [k for k, v in env_vars.items()
                       if isinstance(v, str) and SECRET_VALUE_RE.match(v) and k not in suspicious]
        out.append(Finding(
            check_id="LMB-003",
            title="Lambda function env vars may contain plaintext secrets",
            severity=Severity.HIGH,
            resource=fn.address,
            description=(
                f"Secret-like env var keys: {suspicious}." if suspicious else
                "No secret-like environment variables."
            ),
            recommendation="Move secrets to Secrets Manager or SSM SecureString.",
            passed=not suspicious,
        ))
        url_cfg = url_by_fn.get(name)
        if url_cfg is not None:
            auth = url_cfg.get("authorization_type", "")
            out.append(Finding(
                check_id="LMB-002",
                title="Lambda function URL has AuthType=NONE",
                severity=Severity.HIGH,
                resource=fn.address,
                description=(
                    f"authorization_type = {auth}." if auth == "AWS_IAM"
                    else f"authorization_type = {auth or 'NONE'}; URL is public."
                ),
                recommendation="Set authorization_type = \"AWS_IAM\" and grant invoke via IAM.",
                passed=auth == "AWS_IAM",
            ))
    for p in ctx.resources("aws_lambda_permission"):
        principal = p.values.get("principal", "")
        scoped = bool(p.values.get("source_arn")) or bool(p.values.get("source_account"))
        is_public = principal == "*" or principal.endswith(".amazonaws.com") is False and principal != ""
        # Only flag when principal is "*" AND unscoped — service principals
        # with a source_arn/source_account are fine.
        offending = principal == "*" and not scoped
        out.append(Finding(
            check_id="LMB-004",
            title="Lambda resource policy allows wildcard principal",
            severity=Severity.CRITICAL,
            resource=p.address,
            description=(
                "principal = '*' with no source_arn/source_account condition."
                if offending else
                "Permission is scoped."
            ),
            recommendation=(
                "Narrow principal or add source_arn / source_account on "
                "wildcard-principal permissions."
            ),
            passed=not offending,
        ))
    return out


def _first_map(val):
    if isinstance(val, list) and val:
        first = val[0]
        return first if isinstance(first, dict) else {}
    return val if isinstance(val, dict) else {}


# ---------------------------------------------------------------------------
# KMS
# ---------------------------------------------------------------------------

def _kms(ctx) -> list[Finding]:
    out: list[Finding] = []
    for key in ctx.resources("aws_kms_key"):
        spec = (key.values.get("customer_master_key_spec") or "SYMMETRIC_DEFAULT")
        if spec != "SYMMETRIC_DEFAULT":
            continue
        rotation = bool(key.values.get("enable_key_rotation"))
        out.append(Finding(
            check_id="KMS-001",
            title="KMS customer-managed key has rotation disabled",
            severity=Severity.MEDIUM,
            resource=key.address,
            description=(
                "enable_key_rotation = true." if rotation else
                "enable_key_rotation is false or unset."
            ),
            recommendation="Set enable_key_rotation = true.",
            passed=rotation,
        ))
        doc = _parse_policy(key.values.get("policy"))
        offenders: list[str] = []
        for stmt in iter_allow(doc):
            actions = as_list(stmt.get("Action"))
            if any(a in ("*", "kms:*") for a in actions if isinstance(a, str)):
                offenders.append(stmt.get("Sid") or "<unsid>")
        out.append(Finding(
            check_id="KMS-002",
            title="KMS key policy grants wildcard KMS actions",
            severity=Severity.HIGH,
            resource=key.address,
            description=(
                f"Statement(s) {offenders} grant kms:*." if offenders
                else "No wildcard kms:* grants."
            ),
            recommendation="Replace kms:* with specific actions per caller.",
            passed=not offenders,
        ))
    return out


# ---------------------------------------------------------------------------
# SSM
# ---------------------------------------------------------------------------

def _ssm(ctx) -> list[Finding]:
    out: list[Finding] = []
    for p in ctx.resources("aws_ssm_parameter"):
        name = p.values.get("name", "") or ""
        ptype = p.values.get("type", "")
        if SECRET_NAME_RE.search(name) and ptype != "SecureString":
            out.append(Finding(
                check_id="SSM-001",
                title="SSM Parameter with secret-like name is not a SecureString",
                severity=Severity.HIGH,
                resource=p.address,
                description=f"Parameter '{name}' is stored as {ptype or 'String'}.",
                recommendation="Set type = \"SecureString\".",
                passed=False,
            ))
        if ptype == "SecureString":
            key = p.values.get("key_id", "") or ""
            passed = bool(key) and "alias/aws/ssm" not in key
            out.append(Finding(
                check_id="SSM-002",
                title="SSM SecureString uses the default AWS-managed key",
                severity=Severity.MEDIUM,
                resource=p.address,
                description=(
                    f"key_id = {key}." if passed else
                    "key_id unset or alias/aws/ssm; using AWS-managed key."
                ),
                recommendation="Set key_id to a customer-managed KMS key ARN.",
                passed=passed,
            ))
    return out
