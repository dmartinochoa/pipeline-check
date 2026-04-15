"""Terraform IAM checks — scoped to CI/CD service roles.

IAM-001  Role has AdministratorAccess                         CRITICAL  CICD-SEC-2
IAM-002  Role has wildcard Action in any policy               HIGH      CICD-SEC-2
IAM-003  Role has no permissions boundary                     MEDIUM    CICD-SEC-2
IAM-004  Role can iam:PassRole with Resource: "*"             HIGH      CICD-SEC-2
IAM-005  Trust policy allows external principal without       HIGH      CICD-SEC-2
         sts:ExternalId condition
IAM-006  Wildcard Resource on sensitive scoped actions        MEDIUM    CICD-SEC-2

"Scoped to CI/CD roles" means only ``aws_iam_role`` resources whose
``assume_role_policy`` allows assumption by CodeBuild, CodePipeline, or
CodeDeploy service principals are inspected.

IAM-002/004/006 inspect every policy reachable from the role: inline
``aws_iam_role_policy``, inline blocks on the role itself, customer-
managed ``aws_iam_policy`` joined through ``aws_iam_role_policy_attachment``,
and the ``managed_policy_arns`` attribute on the role.
"""
from __future__ import annotations

import json
from typing import Iterable

from .base import TerraformBaseCheck, TerraformResource
from ..base import Finding, Severity

_CICD_SERVICE_PRINCIPALS = {
    "codebuild.amazonaws.com",
    "codepipeline.amazonaws.com",
    "codedeploy.amazonaws.com",
}

_ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"

# Actions that are high-risk when paired with an unscoped Resource.
# A scoped action over Resource:"*" is the classic "least-privilege theatre"
# finding that IAM-002 (which only catches Action:"*") misses.
_SENSITIVE_ACTION_PREFIXES = (
    "s3:", "kms:", "secretsmanager:", "ssm:", "iam:", "sts:",
    "dynamodb:", "lambda:", "ec2:",
)
_SENSITIVE_ACTION_EXACT = {
    "*",  # handled by IAM-002 but included for completeness
}


def _parse(raw) -> dict:
    if not raw:
        return {}
    if isinstance(raw, dict):
        return raw
    try:
        return json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return {}


def _role_is_cicd(values: dict) -> bool:
    doc = _parse(values.get("assume_role_policy"))
    for stmt in doc.get("Statement", []):
        principal = stmt.get("Principal", {}) or {}
        services = principal.get("Service", [])
        if isinstance(services, str):
            services = [services]
        if any(s in _CICD_SERVICE_PRINCIPALS for s in services):
            return True
    return False


def _iter_allow_statements(doc: dict) -> Iterable[dict]:
    for stmt in doc.get("Statement", []):
        if stmt.get("Effect") == "Allow":
            yield stmt


def _as_list(v) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _has_wildcard_action(doc: dict) -> bool:
    for stmt in _iter_allow_statements(doc):
        if "*" in _as_list(stmt.get("Action")):
            return True
    return False


def _statements_with_passrole_wildcard(doc: dict) -> bool:
    for stmt in _iter_allow_statements(doc):
        actions = _as_list(stmt.get("Action"))
        if not any(
            a == "iam:PassRole" or a == "iam:*" or a == "*"
            for a in actions
        ):
            continue
        resources = _as_list(stmt.get("Resource"))
        if "*" in resources:
            return True
    return False


def _sensitive_wildcard_resource(doc: dict) -> list[str]:
    """Return sensitive actions that are paired with Resource:'*'."""
    hits: list[str] = []
    for stmt in _iter_allow_statements(doc):
        actions = _as_list(stmt.get("Action"))
        # IAM-002 already covers Action:"*" — don't double-report here.
        if "*" in actions:
            continue
        resources = _as_list(stmt.get("Resource"))
        if "*" not in resources:
            continue
        for a in actions:
            if isinstance(a, str) and (
                a.startswith(_SENSITIVE_ACTION_PREFIXES)
                or a in _SENSITIVE_ACTION_EXACT
            ):
                hits.append(a)
    return hits


class IAMChecks(TerraformBaseCheck):

    def run(self) -> list[Finding]:
        cicd_roles: list[TerraformResource] = [
            r for r in self.ctx.resources("aws_iam_role")
            if _role_is_cicd(r.values)
        ]
        if not cicd_roles:
            return []

        # Index ancillary resources.
        attachments: dict[str, list[str]] = {}
        for r in self.ctx.resources("aws_iam_role_policy_attachment"):
            role = r.values.get("role", "")
            arn = r.values.get("policy_arn", "")
            if role and arn:
                attachments.setdefault(role, []).append(arn)

        inline_separate: dict[str, list[tuple[str, dict]]] = {}
        for r in self.ctx.resources("aws_iam_role_policy"):
            role = r.values.get("role", "")
            if not role:
                continue
            pname = r.values.get("name") or r.name
            doc = _parse(r.values.get("policy"))
            inline_separate.setdefault(role, []).append((pname, doc))

        # Customer-managed policies, indexed both by ARN and by name
        # (Terraform lets attachments reference either — "arn" attribute is
        # always present, but we keep name as a fallback).
        customer_policies_by_arn: dict[str, dict] = {}
        customer_policies_by_name: dict[str, dict] = {}
        for r in self.ctx.resources("aws_iam_policy"):
            doc = _parse(r.values.get("policy"))
            arn = r.values.get("arn")
            pname = r.values.get("name") or r.name
            if arn:
                customer_policies_by_arn[arn] = doc
            customer_policies_by_name[pname] = doc

        findings: list[Finding] = []
        for r in cicd_roles:
            role_name = r.values.get("name") or r.name

            managed_arns = list(r.values.get("managed_policy_arns") or [])
            managed_arns.extend(attachments.get(role_name, []))

            # Collect every policy document visible for this role.
            policy_docs: list[tuple[str, dict]] = []
            policy_docs.extend(inline_separate.get(role_name, []))
            for block in (r.values.get("inline_policy") or []):
                policy_docs.append(
                    (block.get("name", "inline"), _parse(block.get("policy")))
                )
            for arn in managed_arns:
                if arn in customer_policies_by_arn:
                    policy_docs.append((arn, customer_policies_by_arn[arn]))

            findings.append(_iam001_admin_access(managed_arns, role_name))
            findings.append(_iam002_wildcard_action(policy_docs, role_name))
            findings.append(_iam003_permission_boundary(r.values, role_name))
            findings.append(_iam004_passrole_wildcard(policy_docs, role_name))
            findings.append(_iam005_external_trust(r.values, role_name))
            findings.append(_iam006_wildcard_resource(policy_docs, role_name))
        return findings


def _iam001_admin_access(arns: Iterable[str], role_name: str) -> Finding:
    has_admin = _ADMIN_POLICY_ARN in arns
    desc = (
        f"Role '{role_name}' has the AWS-managed AdministratorAccess policy "
        f"attached, granting unrestricted access to all AWS services and "
        f"resources."
        if has_admin else
        f"Role '{role_name}' does not have AdministratorAccess attached."
    )
    return Finding(
        check_id="IAM-001",
        title="CI/CD role has AdministratorAccess policy attached",
        severity=Severity.CRITICAL,
        resource=role_name,
        description=desc,
        recommendation=(
            "Replace AdministratorAccess with least-privilege policies that "
            "grant only the specific actions and resources required."
        ),
        passed=not has_admin,
    )


def _iam002_wildcard_action(policy_docs: list[tuple[str, dict]], role_name: str) -> Finding:
    wildcard_policies = [name for name, doc in policy_docs if _has_wildcard_action(doc)]
    passed = not wildcard_policies
    desc = (
        f"No policies attached to '{role_name}' use Action: '*'."
        if passed else
        f"Policy/policies {wildcard_policies} attached to role '{role_name}' "
        f"use Action: '*', granting unrestricted access to one or more services."
    )
    return Finding(
        check_id="IAM-002",
        title="CI/CD role has wildcard Action in attached policy",
        severity=Severity.HIGH,
        resource=role_name,
        description=desc,
        recommendation=(
            "Replace wildcard actions with the specific IAM actions the role "
            "actually requires."
        ),
        passed=passed,
    )


def _iam003_permission_boundary(values: dict, role_name: str) -> Finding:
    boundary = values.get("permissions_boundary") or ""
    passed = bool(boundary)
    desc = (
        f"Role '{role_name}' has a permissions boundary: {boundary}."
        if passed else
        f"Role '{role_name}' has no permissions boundary."
    )
    return Finding(
        check_id="IAM-003",
        title="CI/CD role has no permission boundary",
        severity=Severity.MEDIUM,
        resource=role_name,
        description=desc,
        recommendation=(
            "Attach a permissions boundary to each CI/CD service role."
        ),
        passed=passed,
    )


def _iam004_passrole_wildcard(policy_docs: list[tuple[str, dict]], role_name: str) -> Finding:
    offenders = [name for name, doc in policy_docs if _statements_with_passrole_wildcard(doc)]
    passed = not offenders
    desc = (
        f"No policy on '{role_name}' grants iam:PassRole with Resource: '*'."
        if passed else
        f"Policy/policies {offenders} attached to role '{role_name}' grant "
        f"iam:PassRole with Resource: '*'. This allows the build to assume "
        f"arbitrary service roles in the account, a classic privilege-escalation path."
    )
    return Finding(
        check_id="IAM-004",
        title="CI/CD role can PassRole to any role",
        severity=Severity.HIGH,
        resource=role_name,
        description=desc,
        recommendation=(
            "Restrict iam:PassRole to the specific role ARNs the pipeline must "
            "hand off to (e.g. CodeDeploy/ECS task roles). Combine with an "
            "iam:PassedToService condition so the role can only be passed to "
            "the intended service."
        ),
        passed=passed,
    )


def _iam005_external_trust(values: dict, role_name: str) -> Finding:
    doc = _parse(values.get("assume_role_policy"))
    bad_statements: list[str] = []

    for idx, stmt in enumerate(_iter_allow_statements(doc)):
        principal = stmt.get("Principal", {}) or {}
        # Only interested in AWS account principals; service principals are
        # trust boundaries managed by AWS, not arbitrary external accounts.
        aws = principal.get("AWS") if isinstance(principal, dict) else None
        if not aws:
            continue

        conditions = stmt.get("Condition", {}) or {}
        has_external_id = any(
            "sts:ExternalId" in (inner or {})
            for inner in conditions.values()
            if isinstance(inner, dict)
        )
        if not has_external_id:
            bad_statements.append(f"stmt[{idx}]")

    passed = not bad_statements
    desc = (
        f"Trust policy on '{role_name}' either has no external principals or "
        f"every external-principal statement enforces sts:ExternalId."
        if passed else
        f"Trust policy on '{role_name}' allows assumption by an external AWS "
        f"account principal in {bad_statements} without requiring "
        f"sts:ExternalId. This is vulnerable to the confused-deputy pattern."
    )
    return Finding(
        check_id="IAM-005",
        title="CI/CD role trust policy missing sts:ExternalId",
        severity=Severity.HIGH,
        resource=role_name,
        description=desc,
        recommendation=(
            "Add a Condition block requiring sts:ExternalId for any statement "
            "that allows external AWS accounts to assume this role."
        ),
        passed=passed,
    )


def _iam006_wildcard_resource(policy_docs: list[tuple[str, dict]], role_name: str) -> Finding:
    hits: dict[str, list[str]] = {}
    for name, doc in policy_docs:
        sensitive = _sensitive_wildcard_resource(doc)
        if sensitive:
            hits[name] = sorted(set(sensitive))

    passed = not hits
    if passed:
        desc = (
            f"No policy on '{role_name}' pairs a sensitive service action "
            f"with Resource: '*'."
        )
    else:
        summary = ", ".join(f"{k}→{v}" for k, v in hits.items())
        desc = (
            f"Policy/policies on role '{role_name}' grant sensitive actions "
            f"over Resource: '*': {summary}. This widens blast radius when a "
            f"build is compromised."
        )
    return Finding(
        check_id="IAM-006",
        title="Sensitive actions granted with wildcard Resource",
        severity=Severity.MEDIUM,
        resource=role_name,
        description=desc,
        recommendation=(
            "Scope the Resource element of each statement to the specific "
            "ARNs the pipeline must operate on (bucket ARNs, key ARNs, "
            "secret ARNs, role ARNs). Reserve Resource: '*' for actions that "
            "genuinely require it (e.g. ec2:Describe*)."
        ),
        passed=passed,
    )
