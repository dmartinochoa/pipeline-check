"""CloudFormation Phase-2 parity. CA-*, CCM-*, LMB-*, KMS-*, SSM-*.

Mirrors ``checks/terraform/services.py``. Notes:

- **CCM-001** (approval rule template attached): AWS CloudFormation
  does not provide a resource to associate an approval rule template
  with a repository, so the check is omitted here rather than raising
  false positives on every CFN CodeCommit repo.
- **CCM-003**: CFN CodeCommit triggers are inline on the repo
  resource, not a separate resource.
"""
from __future__ import annotations

import json
from typing import Any

from .._context import statement_is_constrained
from .._iam_policy import as_list, iter_allow, public_principal
from .._patterns import SECRET_NAME_RE, SECRET_VALUE_RE
from ..base import Finding, Severity
from .base import (
    CloudFormationBaseCheck,
    CloudFormationContext,
    as_str,
    is_intrinsic,
    is_true,
)


def _principal_is_only_account_root(stmt: dict[str, Any]) -> bool:
    """True when a statement's principal is exclusively the account root.

    The default/required KMS key policy grants ``kms:*`` to
    ``arn:aws:iam::<acct>:root`` (literal or via ``Fn::Sub`` with
    ``${AWS::AccountId}``). That root statement is AWS's recommended
    baseline (it lets IAM policies govern access), not an over-broad
    grant, so KMS-002 must not flag it.
    """
    principal = stmt.get("Principal")
    if not isinstance(principal, dict) or set(principal) - {"AWS"}:
        return False
    aws = principal.get("AWS")
    values = aws if isinstance(aws, list) else [aws]
    if not values:
        return False
    for v in values:
        if isinstance(v, str) and v.endswith(":root"):
            continue
        if (isinstance(v, dict) and isinstance(v.get("Fn::Sub"), str)
                and v["Fn::Sub"].endswith(":root")):
            continue
        return False
    return True


class ServiceChecks(CloudFormationBaseCheck):

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

def _codeartifact(ctx: CloudFormationContext) -> list[Finding]:
    out: list[Finding] = []
    for d in ctx.resources("AWS::CodeArtifact::Domain"):
        key = d.properties.get("EncryptionKey")
        key_str = as_str(key)
        if key_str:
            # Literal string: pass unless it's an AWS-owned alias.
            passed = "alias/aws/" not in key_str
        elif is_intrinsic(key) and _is_cmk_intrinsic(key, ctx):
            # Ref/GetAtt to an in-template KMS::Key/Alias is the only
            # practical way to point at a stack-defined CMK (CCM-002
            # handles it the same way).
            passed = True
            key_str = "<intrinsic CMK reference>"
        else:
            passed = False
        out.append(Finding(
            check_id="CA-001",
            title="CodeArtifact domain not encrypted with customer KMS CMK",
            severity=Severity.MEDIUM,
            resource=d.address,
            description=(
                f"EncryptionKey: {key_str}." if passed
                else "EncryptionKey not set; domain will use the AWS-owned key."
            ),
            recommendation="Set EncryptionKey to a CMK ARN at creation.",
            passed=passed,
        ))
        doc = d.properties.get("PermissionsPolicyDocument")
        if doc is not None:
            policy = _parse_policy(doc)
            # A wildcard principal narrowed by aws:PrincipalOrgID (the
            # documented org-sharing idiom) is not cross-account exposure.
            offenders = [
                i for i, s in enumerate(iter_allow(policy))
                if public_principal(s) and not statement_is_constrained(s)
            ]
            out.append(Finding(
                check_id="CA-003",
                title="CodeArtifact domain policy allows cross-account wildcard",
                severity=Severity.CRITICAL,
                resource=d.address,
                description=(
                    f"Allow statement(s) {offenders} grant Principal: '*'." if offenders
                    else "No wildcard-principal Allow statements."
                ),
                recommendation=(
                    "Remove ``Principal: '*'`` or add an aws:PrincipalOrgID condition."
                ),
                passed=not offenders,
            ))
    for r in ctx.resources("AWS::CodeArtifact::Repository"):
        conns = r.properties.get("ExternalConnections") or []
        public = [c for c in conns if isinstance(c, str) and c.startswith("public:")]
        out.append(Finding(
            check_id="CA-002",
            title="CodeArtifact repository has a public external connection",
            severity=Severity.HIGH,
            resource=r.address,
            description=(
                f"Public ExternalConnections: {public}." if public
                else "No public ExternalConnections declared."
            ),
            recommendation=(
                "Route public consumption through a pull-through cache with an allow-list."
            ),
            passed=not public,
        ))
        doc = r.properties.get("PermissionsPolicyDocument")
        if doc is not None:
            policy = _parse_policy(doc)
            over_broad = False
            for stmt in iter_allow(policy):
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
                title="CodeArtifact repo policy grants ``codeartifact:*`` with ``Resource '*'``",
                severity=Severity.HIGH,
                resource=r.address,
                description=(
                    "Policy grants codeartifact:* with Resource '*'." if over_broad
                    else "Actions and resources are scoped."
                ),
                recommendation="Scope actions and resources on every Allow statement.",
                passed=not over_broad,
            ))
    return out


# ---------------------------------------------------------------------------
# CodeCommit. CCM-002 (KMS), CCM-003 (cross-account triggers).
# CCM-001 omitted (no CFN resource for approval-rule template association).
# ---------------------------------------------------------------------------

_KMS_RESOURCE_TYPES = frozenset({
    "AWS::KMS::Key",
    "AWS::KMS::Alias",
})


def _is_cmk_intrinsic(value: Any, ctx: CloudFormationContext) -> bool:
    """Return True when *value* is an intrinsic that references a KMS resource.

    Handles ``{"Ref": "LogicalId"}`` and ``{"Fn::GetAtt": ["LogicalId", ...]}``
    when the logical ID maps to an ``AWS::KMS::Key`` or ``AWS::KMS::Alias``
    resource in the template. If the intrinsic targets something else or is
    unresolvable, returns False so the rule keeps its conservative default.
    """
    if not isinstance(value, dict) or len(value) != 1:
        return False
    (intrinsic_key, inner) = next(iter(value.items()))
    if intrinsic_key == "Ref" and isinstance(inner, str):
        logical_id = inner
    elif intrinsic_key == "Fn::GetAtt":
        if isinstance(inner, list) and inner:
            logical_id = inner[0]
        elif isinstance(inner, str) and "." in inner:
            logical_id = inner.split(".", 1)[0]
        else:
            return False
    else:
        return False
    kms_logical_ids = {
        res.logical_id
        for res in ctx.resources()
        if res.type in _KMS_RESOURCE_TYPES
    }
    return logical_id in kms_logical_ids


def _codecommit(ctx: CloudFormationContext) -> list[Finding]:
    out: list[Finding] = []
    for r in ctx.resources("AWS::CodeCommit::Repository"):
        key = r.properties.get("KmsKeyId")
        key_str = as_str(key)
        if key_str:
            # Literal string: pass only when it is not the AWS-owned alias.
            passed = "alias/aws/codecommit" not in key_str
        elif is_intrinsic(key) and _is_cmk_intrinsic(key, ctx):
            # Ref/GetAtt to a KMS resource in the template is the standard
            # CFN idiom for a customer-managed key. Treat it as a CMK.
            passed = True
            key_str = "<intrinsic CMK reference>"
        else:
            passed = False
        out.append(Finding(
            check_id="CCM-002",
            title="CodeCommit repository not encrypted with customer KMS CMK",
            severity=Severity.MEDIUM,
            resource=r.address,
            description=(
                f"KmsKeyId: {key_str}." if passed
                else "KmsKeyId unset or AWS-owned; repo uses default encryption."
            ),
            recommendation="Set KmsKeyId to a customer-managed KMS key ARN.",
            passed=passed,
        ))
        # CCM-003: CodeCommit triggers that specify a literal DestinationArn
        # bypass the in-template resource graph and cannot be validated
        # statically for account membership. Flag any literal ARN so
        # reviewers can confirm the target stays within the same account.
        # Destinations expressed via Fn::GetAtt / Ref on in-template
        # SNS/Lambda resources are the recommended pattern and pass.
        triggers = r.properties.get("Triggers") or []
        offenders: list[str] = []
        for trig in triggers:
            if not isinstance(trig, dict):
                continue
            dest = trig.get("DestinationArn")
            if isinstance(dest, str) and dest.count(":") >= 4:
                # Literal ARN — the account field cannot be compared
                # statically; flag for human review.
                offenders.append(dest)
        if triggers:
            out.append(Finding(
                check_id="CCM-003",
                title=(
                    "CodeCommit trigger uses a literal DestinationArn "
                    "that cannot be validated as same-account"
                ),
                severity=Severity.MEDIUM,
                resource=r.address,
                description=(
                    f"Literal DestinationArn(s) in Triggers: {offenders}. "
                    "Static analysis cannot confirm these belong to the same "
                    "account as the repository."
                    if offenders else
                    "All trigger destinations reference template resources, not literal ARNs."
                ),
                recommendation=(
                    "Reference trigger destinations via Fn::GetAtt / Ref on in-template "
                    "SNS/Lambda resources instead of literal ARNs."
                ),
                passed=not offenders,
            ))
    return out


# ---------------------------------------------------------------------------
# Lambda
# ---------------------------------------------------------------------------

def _lambda(ctx: CloudFormationContext) -> list[Finding]:
    out: list[Finding] = []
    url_by_fn_logical: dict[str, dict[str, Any]] = {}
    url_by_fn_name: dict[str, dict[str, Any]] = {}
    for u in ctx.resources("AWS::Lambda::Url"):
        target = u.properties.get("TargetFunctionArn")
        if isinstance(target, str):
            url_by_fn_name[target] = u.properties
        elif isinstance(target, dict):
            if "Ref" in target:
                url_by_fn_logical[target["Ref"]] = u.properties
            elif "Fn::GetAtt" in target:
                att = target["Fn::GetAtt"]
                if isinstance(att, list) and att:
                    url_by_fn_logical[att[0]] = u.properties

    for fn in ctx.resources("AWS::Lambda::Function"):
        signing = fn.properties.get("CodeSigningConfigArn")
        out.append(Finding(
            check_id="LMB-001",
            title="Lambda function has no code-signing config",
            severity=Severity.HIGH,
            resource=fn.address,
            description=(
                f"CodeSigningConfigArn: {signing}." if signing
                else "CodeSigningConfigArn is unset; unsigned code is deployable."
            ),
            recommendation="Set CodeSigningConfigArn on every function that deploys release artifacts.",
            passed=bool(signing),
        ))
        env = fn.properties.get("Environment") or {}
        env_vars: dict[str, object] = {}
        if not is_intrinsic(env):
            raw_vars = env.get("Variables") or {}
            if not is_intrinsic(raw_vars) and isinstance(raw_vars, dict):
                env_vars = raw_vars
        suspicious: list[str] = []
        for k, v in env_vars.items():
            if not isinstance(k, str):
                continue
            if SECRET_NAME_RE.search(k):
                # A secret-like NAME is a finding only when the VALUE is a
                # plaintext literal. A value that merely references a secret
                # (an intrinsic Ref/GetAtt/Sub, a {{resolve:...}} dynamic
                # reference, or a literal ARN) is the recommended pattern,
                # e.g. ``DB_SECRET_ARN: !Ref DbSecret``.
                if is_intrinsic(v):
                    continue
                if isinstance(v, str) and v.startswith(("{{resolve:", "arn:aws:")):
                    continue
                suspicious.append(k)
                continue
            if isinstance(v, str) and SECRET_VALUE_RE.match(v):
                suspicious.append(k)
        out.append(Finding(
            check_id="LMB-003",
            title="Lambda function env vars may contain plaintext secrets",
            severity=Severity.HIGH,
            resource=fn.address,
            description=(
                f"Secret-like env var keys: {suspicious}." if suspicious
                else "No secret-like environment variables."
            ),
            recommendation="Move secrets to Secrets Manager or SSM SecureString.",
            passed=not suspicious,
        ))
        url_props = url_by_fn_logical.get(fn.logical_id)
        if url_props is None:
            fn_name = as_str(fn.properties.get("FunctionName"))
            if fn_name:
                url_props = url_by_fn_name.get(fn_name)
        if url_props is not None:
            auth = as_str(url_props.get("AuthType"))
            out.append(Finding(
                check_id="LMB-002",
                title="Lambda function URL has AuthType=NONE",
                severity=Severity.HIGH,
                resource=fn.address,
                description=(
                    f"AuthType: {auth}." if auth == "AWS_IAM"
                    else f"AuthType: {auth or 'NONE'}; URL is public."
                ),
                recommendation='Set AuthType: "AWS_IAM" and grant invoke via IAM.',
                passed=auth == "AWS_IAM",
            ))

    # Second pass: AWS::Lambda::Url resources whose TargetFunctionArn is a
    # literal cross-stack ARN (no local function to match) are missed by the
    # fn-loop above. Emit LMB-002 directly from the Url resource for any Url
    # that was not already matched by a local function.
    matched_url_addresses: set[str] = set()
    # Collect addresses of Url resources that ARE already covered above.
    for fn in ctx.resources("AWS::Lambda::Function"):
        url_props = url_by_fn_logical.get(fn.logical_id)
        if url_props is None:
            fn_name = as_str(fn.properties.get("FunctionName"))
            if fn_name:
                url_props = url_by_fn_name.get(fn_name)
        if url_props is not None:
            # Record this url's address so we skip it below.
            for u in ctx.resources("AWS::Lambda::Url"):
                if u.properties is url_props:
                    matched_url_addresses.add(u.address)

    for u in ctx.resources("AWS::Lambda::Url"):
        if u.address in matched_url_addresses:
            continue
        # This Url targets a function that is not defined in the template
        # (e.g. a literal cross-stack ARN). Evaluate AuthType directly.
        auth = as_str(u.properties.get("AuthType"))
        out.append(Finding(
            check_id="LMB-002",
            title="Lambda function URL has AuthType=NONE",
            severity=Severity.HIGH,
            resource=u.address,
            description=(
                f"AuthType: {auth}." if auth == "AWS_IAM"
                else f"AuthType: {auth or 'NONE'}; URL is public."
            ),
            recommendation='Set AuthType: "AWS_IAM" and grant invoke via IAM.',
            passed=auth == "AWS_IAM",
        ))

    for p in ctx.resources("AWS::Lambda::Permission"):
        principal = as_str(p.properties.get("Principal"))
        scoped = bool(p.properties.get("SourceArn")) or bool(p.properties.get("SourceAccount"))
        offending = principal == "*" and not scoped
        out.append(Finding(
            check_id="LMB-004",
            title="Lambda resource policy allows wildcard principal",
            severity=Severity.CRITICAL,
            resource=p.address,
            description=(
                "Principal: '*' with no SourceArn/SourceAccount condition."
                if offending else
                "Permission is scoped."
            ),
            recommendation=(
                "Narrow Principal or add SourceArn / SourceAccount on wildcard-principal permissions."
            ),
            passed=not offending,
        ))
    return out


# ---------------------------------------------------------------------------
# KMS
# ---------------------------------------------------------------------------

def _kms(ctx: CloudFormationContext) -> list[Finding]:
    out: list[Finding] = []
    for key in ctx.resources("AWS::KMS::Key"):
        spec = as_str(key.properties.get("KeySpec")) or "SYMMETRIC_DEFAULT"
        if spec != "SYMMETRIC_DEFAULT":
            # Rotation isn't applicable to asymmetric/HMAC keys.
            continue
        rotation = is_true(key.properties.get("EnableKeyRotation"))
        out.append(Finding(
            check_id="KMS-001",
            title="KMS customer-managed key has rotation disabled",
            severity=Severity.MEDIUM,
            resource=key.address,
            description=(
                "EnableKeyRotation: true." if rotation
                else "EnableKeyRotation is false or unset."
            ),
            recommendation="Set EnableKeyRotation: true.",
            passed=rotation,
        ))
        doc = _parse_policy(key.properties.get("KeyPolicy"))
        offenders: list[str] = []
        for stmt in iter_allow(doc):
            actions = as_list(stmt.get("Action"))
            if not any(a in ("*", "kms:*") for a in actions if isinstance(a, str)):
                continue
            # The default/required KMS key policy grants kms:* to the
            # account root so IAM policies can delegate; that root
            # statement is the recommended baseline, not a finding.
            if _principal_is_only_account_root(stmt):
                continue
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

def _ssm(ctx: CloudFormationContext) -> list[Finding]:
    out: list[Finding] = []
    for p in ctx.resources("AWS::SSM::Parameter"):
        name = as_str(p.properties.get("Name"))
        ptype = as_str(p.properties.get("Type"))
        # AWS::SSM::Parameter only supports String/StringList. SecureString
        # creation via CFN isn't supported as of this writing. We still check
        # the Type property defensively because the restriction is evolving.
        if SECRET_NAME_RE.search(name) and ptype != "SecureString":
            out.append(Finding(
                check_id="SSM-001",
                title="SSM Parameter with secret-like name is not a SecureString",
                severity=Severity.HIGH,
                resource=p.address,
                description=(
                    f"Parameter '{name}' has a secret-like name but Type={ptype or 'String'}. "
                    "Note: CFN does not support creating SecureStrings directly, migrate "
                    "the parameter to Secrets Manager or create it out-of-band."
                ),
                recommendation=(
                    "Migrate to AWS::SecretsManager::Secret, or create the SecureString "
                    "via CLI/SDK and reference it from the template via ``{{resolve:ssm-secure:...}}``."
                ),
                passed=False,
            ))
        if ptype == "SecureString":
            key = as_str(p.properties.get("KeyId"))
            passed = bool(key) and "alias/aws/ssm" not in key
            out.append(Finding(
                check_id="SSM-002",
                title="SSM SecureString uses the default AWS-managed key",
                severity=Severity.MEDIUM,
                resource=p.address,
                description=(
                    f"KeyId: {key}." if passed
                    else "KeyId unset or alias/aws/ssm; using AWS-managed key."
                ),
                recommendation="Set KeyId to a customer-managed KMS key ARN.",
                passed=passed,
            ))
    return out


def _parse_policy(raw: object) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}
