"""CloudFormation IAM checks — IAM-001..006, scoped to CI/CD service roles.

CFN differences from Terraform:
  - Inline policies live on the Role itself (``Policies`` property),
    each with ``PolicyName`` + ``PolicyDocument``. There's no separate
    ``aws_iam_role_policy`` resource.
  - Managed policies are listed via ``ManagedPolicyArns``; there's no
    separate attachment resource.
  - ``AWS::IAM::ManagedPolicy`` is the CFN equivalent of
    ``aws_iam_policy``. Attached via name reference or ARN.
  - ``AssumeRolePolicyDocument`` is an inline dict (already parsed),
    not a JSON string.
"""
from __future__ import annotations

from collections.abc import Iterable

from .._iam_policy import (
    ADMIN_POLICY_ARN as _ADMIN_POLICY_ARN,
)
from .._iam_policy import (
    CICD_SERVICE_PRINCIPALS as _CICD_SERVICE_PRINCIPALS,
)
from .._iam_policy import (
    has_wildcard_action as _has_wildcard_action,
)
from .._iam_policy import (
    iter_allow as _iter_allow_statements,
)
from .._iam_policy import (
    passrole_wildcard as _statements_with_passrole_wildcard,
)
from .._iam_policy import (
    sensitive_wildcard as _sensitive_wildcard_resource,
)
from ..base import Finding, Severity
from .base import CloudFormationBaseCheck, CloudFormationResource, as_str


def _role_is_cicd(properties: dict) -> bool:
    doc = properties.get("AssumeRolePolicyDocument")
    if not isinstance(doc, dict):
        return False
    stmts = doc.get("Statement") or []
    if isinstance(stmts, dict):
        stmts = [stmts]
    for stmt in stmts:
        if not isinstance(stmt, dict):
            continue
        principal = stmt.get("Principal") or {}
        services = principal.get("Service", []) if isinstance(principal, dict) else []
        if isinstance(services, str):
            services = [services]
        if any(s in _CICD_SERVICE_PRINCIPALS for s in services):
            return True
    return False


class IAMChecks(CloudFormationBaseCheck):

    def run(self) -> list[Finding]:
        cicd_roles: list[CloudFormationResource] = [
            r for r in self.ctx.resources("AWS::IAM::Role")
            if _role_is_cicd(r.properties)
        ]
        if not cicd_roles:
            return []

        # Index managed policies by logical id so ManagedPolicyArns values
        # of the form {"Ref": "MyManagedPolicy"} can be dereferenced.
        managed_by_logical_id: dict[str, dict] = {}
        for r in self.ctx.resources("AWS::IAM::ManagedPolicy"):
            doc = r.properties.get("PolicyDocument")
            if isinstance(doc, dict):
                managed_by_logical_id[r.logical_id] = doc

        findings: list[Finding] = []
        for r in cicd_roles:
            role_name = as_str(r.properties.get("RoleName")) or r.logical_id
            arns = list(r.properties.get("ManagedPolicyArns") or [])

            policy_docs: list[tuple[str, dict]] = []
            # Inline policies on the Role.
            for inline in (r.properties.get("Policies") or []):
                if not isinstance(inline, dict):
                    continue
                pname = as_str(inline.get("PolicyName")) or "inline"
                doc = inline.get("PolicyDocument")
                if isinstance(doc, dict):
                    policy_docs.append((pname, doc))

            # ManagedPolicyArns may be an ARN string (literal), a
            # ``{"Ref": "X"}`` dict, or a Fn::Sub expression.
            # Dereference Refs against local ManagedPolicy resources.
            for entry in arns:
                if isinstance(entry, dict) and "Ref" in entry:
                    target = entry["Ref"]
                    doc = managed_by_logical_id.get(target)
                    if doc:
                        policy_docs.append((target, doc))

            findings.append(_iam001_admin_access(arns, role_name))
            findings.append(_iam002_wildcard_action(policy_docs, role_name))
            findings.append(_iam003_permission_boundary(r.properties, role_name))
            findings.append(_iam004_passrole_wildcard(policy_docs, role_name))
            findings.append(_iam005_external_trust(r.properties, role_name))
            findings.append(_iam006_wildcard_resource(policy_docs, role_name))
        return findings


def _iam001_admin_access(arns: Iterable, role_name: str) -> Finding:
    # ARNs may be literal strings or intrinsic dicts; only literal
    # strings match ADMIN_POLICY_ARN exactly.
    has_admin = any(
        isinstance(a, str) and a == _ADMIN_POLICY_ARN for a in arns
    )
    desc = (
        f"Role '{role_name}' has the AWS-managed AdministratorAccess policy attached."
        if has_admin else
        f"Role '{role_name}' does not have AdministratorAccess attached."
    )
    return Finding(
        check_id="IAM-001",
        title="CI/CD role has AdministratorAccess policy attached",
        severity=Severity.CRITICAL,
        resource=role_name,
        description=desc,
        recommendation="Replace AdministratorAccess with least-privilege policies.",
        passed=not has_admin,
    )


def _iam002_wildcard_action(policy_docs: list[tuple[str, dict]], role_name: str) -> Finding:
    offenders = [name for name, doc in policy_docs if _has_wildcard_action(doc)]
    passed = not offenders
    desc = (
        f"No policies attached to '{role_name}' use Action: '*'."
        if passed else
        f"Policy/policies {offenders} on role '{role_name}' use Action: '*'."
    )
    return Finding(
        check_id="IAM-002",
        title="CI/CD role has wildcard Action in attached policy",
        severity=Severity.HIGH,
        resource=role_name,
        description=desc,
        recommendation="Replace wildcard actions with specific IAM actions.",
        passed=passed,
    )


def _iam003_permission_boundary(properties: dict, role_name: str) -> Finding:
    boundary = properties.get("PermissionsBoundary")
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
        recommendation="Attach a PermissionsBoundary to each CI/CD service role.",
        passed=passed,
    )


def _iam004_passrole_wildcard(policy_docs: list[tuple[str, dict]], role_name: str) -> Finding:
    offenders = [name for name, doc in policy_docs if _statements_with_passrole_wildcard(doc)]
    passed = not offenders
    desc = (
        f"No policy on '{role_name}' grants iam:PassRole with Resource: '*'."
        if passed else
        f"Policy/policies {offenders} on role '{role_name}' grant iam:PassRole "
        "with Resource: '*' — a classic privilege-escalation path."
    )
    return Finding(
        check_id="IAM-004",
        title="CI/CD role can PassRole to any role",
        severity=Severity.HIGH,
        resource=role_name,
        description=desc,
        recommendation=(
            "Restrict iam:PassRole to specific role ARNs and add an "
            "iam:PassedToService condition."
        ),
        passed=passed,
    )


def _iam005_external_trust(properties: dict, role_name: str) -> Finding:
    doc = properties.get("AssumeRolePolicyDocument") or {}
    if not isinstance(doc, dict):
        doc = {}
    bad: list[str] = []
    for idx, stmt in enumerate(_iter_allow_statements(doc)):
        principal = stmt.get("Principal") or {}
        aws = principal.get("AWS") if isinstance(principal, dict) else None
        if not aws:
            continue
        conditions = stmt.get("Condition") or {}
        has_external_id = any(
            "sts:ExternalId" in (inner or {})
            for inner in conditions.values()
            if isinstance(inner, dict)
        )
        if not has_external_id:
            bad.append(f"stmt[{idx}]")
    passed = not bad
    desc = (
        f"Trust policy on '{role_name}' either has no external AWS principals or "
        "every such statement enforces sts:ExternalId."
        if passed else
        f"Trust policy on '{role_name}' allows assumption by an external AWS "
        f"principal in {bad} without requiring sts:ExternalId."
    )
    return Finding(
        check_id="IAM-005",
        title="CI/CD role trust policy missing sts:ExternalId",
        severity=Severity.HIGH,
        resource=role_name,
        description=desc,
        recommendation=(
            "Add a Condition requiring sts:ExternalId for external AWS-account "
            "principals."
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
        desc = f"No policy on '{role_name}' pairs sensitive actions with Resource: '*'."
    else:
        summary = ", ".join(f"{k}→{v}" for k, v in hits.items())
        desc = (
            f"Policy/policies on role '{role_name}' grant sensitive actions "
            f"over Resource: '*': {summary}."
        )
    return Finding(
        check_id="IAM-006",
        title="Sensitive actions granted with wildcard Resource",
        severity=Severity.MEDIUM,
        resource=role_name,
        description=desc,
        recommendation="Scope the Resource element to specific ARNs.",
        passed=passed,
    )
