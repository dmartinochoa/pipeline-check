"""IAM security checks (scoped to CI/CD service roles).

Checks only IAM roles whose trust policy allows assumption by a CI/CD service
principal (codebuild, codepipeline, codedeploy). This keeps the scope
meaningful and avoids scanning every role in the account.

IAM-001  CI/CD role has AdministratorAccess policy attached  CRITICAL  CICD-SEC-2
IAM-002  CI/CD role has wildcard Action in inline policy      HIGH      CICD-SEC-2
IAM-003  CI/CD role has no permission boundary                MEDIUM    CICD-SEC-2
"""

import json

from botocore.exceptions import ClientError

from .base import AWSBaseCheck, Finding, Severity

_CICD_SERVICE_PRINCIPALS = {
    "codebuild.amazonaws.com",
    "codepipeline.amazonaws.com",
    "codedeploy.amazonaws.com",
}

_ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


def _has_wildcard_action(policy_doc: dict) -> bool:
    """Return True if any Allow statement in *policy_doc* has Action: '*'."""
    for stmt in policy_doc.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        action = stmt.get("Action", [])
        if isinstance(action, str):
            action = [action]
        if "*" in action:
            return True
    return False


class IAMChecks(AWSBaseCheck):

    def run(self) -> list[Finding]:
        client = self.session.client("iam")

        try:
            roles = self._list_cicd_roles(client)
        except ClientError as exc:
            return [Finding(
                check_id="IAM-000",
                title="IAM API access failed",
                severity=Severity.INFO,
                resource="iam",
                description=f"Could not list IAM roles: {exc}. IAM checks skipped.",
                recommendation=(
                    "Ensure the IAM principal has iam:ListRoles permission."
                ),
                passed=False,
            )]

        if not roles:
            return []

        findings: list[Finding] = []
        for role in roles:
            role_name = role["RoleName"]
            findings.extend([
                self._iam001_admin_access(client, role_name),
                self._iam002_wildcard_inline(client, role_name),
                self._iam003_permission_boundary(role, role_name),
            ])
        return findings

    @staticmethod
    def _list_cicd_roles(client) -> list[dict]:
        """Return roles whose trust policy includes a CI/CD service principal."""
        cicd_roles: list[dict] = []
        paginator = client.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page.get("Roles", []):
                try:
                    doc = role.get("AssumeRolePolicyDocument", {})
                    if isinstance(doc, str):
                        doc = json.loads(doc)
                    for stmt in doc.get("Statement", []):
                        principal = stmt.get("Principal", {})
                        services = principal.get("Service", [])
                        if isinstance(services, str):
                            services = [services]
                        if any(s in _CICD_SERVICE_PRINCIPALS for s in services):
                            cicd_roles.append(role)
                            break
                except (KeyError, json.JSONDecodeError):
                    continue
        return cicd_roles

    @staticmethod
    def _iam001_admin_access(client, role_name: str) -> Finding:
        try:
            resp = client.list_attached_role_policies(RoleName=role_name)
            arns = [p["PolicyArn"] for p in resp.get("AttachedPolicies", [])]
            has_admin = _ADMIN_POLICY_ARN in arns
        except ClientError as exc:
            return Finding(
                check_id="IAM-001",
                title="CI/CD role has AdministratorAccess",
                severity=Severity.CRITICAL,
                resource=role_name,
                description=f"Could not list attached policies: {exc}",
                recommendation="Ensure iam:ListAttachedRolePolicies permission.",
                passed=False,
            )

        if has_admin:
            desc = (
                f"Role '{role_name}' has the AWS-managed AdministratorAccess policy "
                f"attached, granting unrestricted access to all AWS services and "
                f"resources. A compromised pipeline can perform any action in the account."
            )
        else:
            desc = f"Role '{role_name}' does not have AdministratorAccess attached."

        return Finding(
            check_id="IAM-001",
            title="CI/CD role has AdministratorAccess policy attached",
            severity=Severity.CRITICAL,
            resource=role_name,
            description=desc,
            recommendation=(
                "Replace AdministratorAccess with least-privilege policies that grant "
                "only the specific actions and resources required by the pipeline. "
                "Use IAM Access Analyzer to identify unused permissions."
            ),
            passed=not has_admin,
        )

    @staticmethod
    def _iam002_wildcard_inline(client, role_name: str) -> Finding:
        try:
            policy_names_resp = client.list_role_policies(RoleName=role_name)
            policy_names: list[str] = policy_names_resp.get("PolicyNames", [])
        except ClientError as exc:
            return Finding(
                check_id="IAM-002",
                title="CI/CD role has wildcard Action in inline policy",
                severity=Severity.HIGH,
                resource=role_name,
                description=f"Could not list inline policies: {exc}",
                recommendation="Ensure iam:ListRolePolicies permission.",
                passed=False,
            )

        wildcard_policies: list[str] = []
        for pname in policy_names:
            try:
                resp = client.get_role_policy(RoleName=role_name, PolicyName=pname)
                doc = resp.get("PolicyDocument", {})
                if isinstance(doc, str):
                    doc = json.loads(doc)
                if _has_wildcard_action(doc):
                    wildcard_policies.append(pname)
            except (ClientError, json.JSONDecodeError):
                continue

        passed = not wildcard_policies

        if passed:
            desc = f"No inline policies on '{role_name}' use wildcard Action."
        else:
            desc = (
                f"Inline policy/policies {wildcard_policies} on role '{role_name}' "
                f"use Action: '*', granting unrestricted access to one or more AWS "
                f"services. This violates least-privilege and widens the blast radius "
                f"of a compromised build."
            )

        return Finding(
            check_id="IAM-002",
            title="CI/CD role has wildcard Action in inline policy",
            severity=Severity.HIGH,
            resource=role_name,
            description=desc,
            recommendation=(
                "Replace wildcard actions with the specific IAM actions the role "
                "actually requires. Use CloudTrail and IAM Access Analyzer last-access "
                "data to identify the minimal required action set."
            ),
            passed=passed,
        )

    @staticmethod
    def _iam003_permission_boundary(role: dict, role_name: str) -> Finding:
        boundary = role.get("PermissionsBoundary", {})
        passed = bool(boundary.get("PermissionsBoundaryArn"))

        if passed:
            desc = (
                f"Role '{role_name}' has a permissions boundary: "
                f"{boundary['PermissionsBoundaryArn']}."
            )
        else:
            desc = (
                f"Role '{role_name}' has no permissions boundary. Without a boundary, "
                f"the role's effective permissions are limited only by the attached "
                f"policies, and there is no guardrail preventing privilege escalation "
                f"if the policy is misconfigured."
            )

        return Finding(
            check_id="IAM-003",
            title="CI/CD role has no permission boundary",
            severity=Severity.MEDIUM,
            resource=role_name,
            description=desc,
            recommendation=(
                "Attach a permissions boundary to each CI/CD service role to define "
                "the maximum permissions it can ever be granted, even if its policies "
                "are accidentally over-permissioned."
            ),
            passed=passed,
        )
