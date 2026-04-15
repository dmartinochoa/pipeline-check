"""Terraform IAM checks — scoped to CI/CD service roles (IAM-001 … IAM-003).

Only ``aws_iam_role`` resources whose ``assume_role_policy`` allows assumption
by a CI/CD service principal (codebuild, codepipeline, codedeploy) are scanned.
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


def _role_is_cicd(values: dict) -> bool:
    raw = values.get("assume_role_policy")
    if not raw:
        return False
    try:
        doc = json.loads(raw) if isinstance(raw, str) else raw
    except json.JSONDecodeError:
        return False
    for stmt in doc.get("Statement", []):
        principal = stmt.get("Principal", {}) or {}
        services = principal.get("Service", [])
        if isinstance(services, str):
            services = [services]
        if any(s in _CICD_SERVICE_PRINCIPALS for s in services):
            return True
    return False


def _has_wildcard_action(policy_doc: dict) -> bool:
    for stmt in policy_doc.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        action = stmt.get("Action", [])
        if isinstance(action, str):
            action = [action]
        if "*" in action:
            return True
    return False


class IAMChecks(TerraformBaseCheck):

    def run(self) -> list[Finding]:
        cicd_roles: list[TerraformResource] = [
            r for r in self.ctx.resources("aws_iam_role")
            if _role_is_cicd(r.values)
        ]
        if not cicd_roles:
            return []

        # Index attachments and inline policies by role name.
        attachments: dict[str, list[str]] = {}
        for r in self.ctx.resources("aws_iam_role_policy_attachment"):
            role = r.values.get("role", "")
            arn = r.values.get("policy_arn", "")
            if role and arn:
                attachments.setdefault(role, []).append(arn)

        inline_policies: dict[str, list[tuple[str, str]]] = {}
        for r in self.ctx.resources("aws_iam_role_policy"):
            role = r.values.get("role", "")
            policy_name = r.values.get("name") or r.name
            policy_text = r.values.get("policy", "") or ""
            if role:
                inline_policies.setdefault(role, []).append((policy_name, policy_text))

        findings: list[Finding] = []
        for r in cicd_roles:
            role_name = r.values.get("name") or r.name
            managed_arns = list(r.values.get("managed_policy_arns") or [])
            managed_arns.extend(attachments.get(role_name, []))
            findings.append(_iam001_admin_access(managed_arns, role_name))
            findings.append(_iam002_wildcard_inline(
                inline_policies.get(role_name, []), r.values.get("inline_policy", []) or [],
                role_name,
            ))
            findings.append(_iam003_permission_boundary(r.values, role_name))
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


def _iam002_wildcard_inline(
    inline_from_separate: list[tuple[str, str]],
    inline_from_role: list[dict],
    role_name: str,
) -> Finding:
    wildcard_policies: list[str] = []

    for pname, ptext in inline_from_separate:
        try:
            doc = json.loads(ptext) if isinstance(ptext, str) else ptext
        except json.JSONDecodeError:
            continue
        if _has_wildcard_action(doc or {}):
            wildcard_policies.append(pname)

    for block in inline_from_role:
        pname = block.get("name", "inline")
        raw = block.get("policy", "")
        try:
            doc = json.loads(raw) if isinstance(raw, str) else raw
        except json.JSONDecodeError:
            continue
        if _has_wildcard_action(doc or {}):
            wildcard_policies.append(pname)

    passed = not wildcard_policies
    desc = (
        f"No inline policies on '{role_name}' use wildcard Action."
        if passed else
        f"Inline policy/policies {wildcard_policies} on role '{role_name}' "
        f"use Action: '*', granting unrestricted access."
    )
    return Finding(
        check_id="IAM-002",
        title="CI/CD role has wildcard Action in inline policy",
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
