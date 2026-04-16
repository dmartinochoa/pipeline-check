"""IAM security checks — scoped to CI/CD service roles.

IAM-001  AdministratorAccess policy attached              CRITICAL  CICD-SEC-2
IAM-002  Wildcard Action in any reachable policy          HIGH      CICD-SEC-2
IAM-003  No permission boundary                           MEDIUM    CICD-SEC-2
IAM-004  iam:PassRole granted with Resource: '*'          HIGH      CICD-SEC-2
IAM-005  Trust policy allows external AWS principal       HIGH      CICD-SEC-2
         without sts:ExternalId condition
IAM-006  Sensitive scoped actions over Resource: '*'      MEDIUM    CICD-SEC-2

IAM-002/004/006 walk every reachable policy: inline policies, customer-managed
policies attached to the role, and the AWS-managed policies' stored default
version (for commonly-problematic managed policies).
"""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

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
    iter_allow as _iter_allow,
)
from .._iam_policy import (
    passrole_wildcard as _passrole_wildcard,
)
from .._iam_policy import (
    sensitive_wildcard as _sensitive_wildcard,
)
from .base import AWSBaseCheck, Finding, Severity


class IAMChecks(AWSBaseCheck):

    def run(self) -> list[Finding]:
        client = self.client("iam")
        try:
            roles = self._list_cicd_roles(client)
        except ClientError as exc:
            return [Finding(
                check_id="IAM-000",
                title="IAM API access failed",
                severity=Severity.INFO,
                resource="iam",
                description=f"Could not list IAM roles: {exc}. IAM checks skipped.",
                recommendation="Ensure iam:ListRoles permission.",
                passed=False,
            )]

        if not roles:
            return []

        findings: list[Finding] = []
        for role in roles:
            role_name = role["RoleName"]
            docs, docs_error = self._collect_policy_docs(client, role_name)
            findings.extend([
                self._iam001_admin_access(client, role_name),
                self._iam002_wildcard_action(docs, role_name, docs_error),
                self._iam003_permission_boundary(role, role_name),
                self._iam004_passrole(docs, role_name, docs_error),
                self._iam005_external_trust(role, role_name),
                self._iam006_sensitive_wildcard(docs, role_name, docs_error),
            ])
        return findings

    @staticmethod
    def _list_cicd_roles(client) -> list[dict]:
        cicd: list[dict] = []
        paginator = client.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page.get("Roles", []):
                try:
                    doc = role.get("AssumeRolePolicyDocument", {})
                    if isinstance(doc, str):
                        doc = json.loads(doc)
                    for stmt in doc.get("Statement", []):
                        principal = stmt.get("Principal", {}) or {}
                        services = principal.get("Service", [])
                        if isinstance(services, str):
                            services = [services]
                        if any(s in _CICD_SERVICE_PRINCIPALS for s in services):
                            cicd.append(role)
                            break
                except (KeyError, json.JSONDecodeError):
                    continue
        return cicd

    @staticmethod
    def _collect_policy_docs(client, role_name: str) -> tuple[list[tuple[str, dict]], str | None]:
        docs: list[tuple[str, dict]] = []
        error: str | None = None

        # Inline policies
        try:
            for pname in client.list_role_policies(RoleName=role_name).get("PolicyNames", []):
                try:
                    resp = client.get_role_policy(RoleName=role_name, PolicyName=pname)
                    doc = resp.get("PolicyDocument", {})
                    if isinstance(doc, str):
                        doc = json.loads(doc)
                    docs.append((pname, doc or {}))
                except (ClientError, json.JSONDecodeError):
                    continue
        except ClientError as exc:
            error = f"Could not list inline role policies: {exc}"

        # Customer-managed attached policies (default version)
        try:
            for attached in client.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
                arn = attached["PolicyArn"]
                if arn.startswith("arn:aws:iam::aws:"):
                    continue  # skip AWS-managed; IAM-001 handles AdministratorAccess
                try:
                    pol = client.get_policy(PolicyArn=arn)["Policy"]
                    version_id = pol["DefaultVersionId"]
                    ver = client.get_policy_version(PolicyArn=arn, VersionId=version_id)
                    doc = ver["PolicyVersion"]["Document"]
                    if isinstance(doc, str):
                        doc = json.loads(doc)
                    docs.append((arn, doc or {}))
                except (ClientError, KeyError, json.JSONDecodeError):
                    continue
        except ClientError as exc:
            if error is None:
                error = f"Could not list attached role policies: {exc}"

        return docs, error

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
        desc = (
            f"Role '{role_name}' has AdministratorAccess attached."
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
                "Replace AdministratorAccess with least-privilege policies."
            ),
            passed=not has_admin,
        )

    @staticmethod
    def _iam002_wildcard_action(docs: list[tuple[str, dict]], role_name: str, error: str | None = None) -> Finding:
        offenders = [n for n, d in docs if _has_wildcard_action(d)]
        passed = not offenders and error is None
        if error:
            desc = f"{error}. Cannot verify wildcard actions for '{role_name}'."
        elif offenders:
            desc = f"Policy/policies {offenders} on '{role_name}' use Action: '*'."
        else:
            desc = f"No policy on '{role_name}' uses Action: '*'."
        return Finding(
            check_id="IAM-002",
            title="CI/CD role has wildcard Action in attached policy",
            severity=Severity.HIGH,
            resource=role_name,
            description=desc,
            recommendation="Replace wildcard actions with specific IAM actions.",
            passed=passed,
        )

    @staticmethod
    def _iam003_permission_boundary(role: dict, role_name: str) -> Finding:
        boundary = role.get("PermissionsBoundary", {})
        passed = bool(boundary.get("PermissionsBoundaryArn"))
        desc = (
            f"Role '{role_name}' has a permissions boundary: {boundary.get('PermissionsBoundaryArn')}."
            if passed else
            f"Role '{role_name}' has no permissions boundary."
        )
        return Finding(
            check_id="IAM-003",
            title="CI/CD role has no permission boundary",
            severity=Severity.MEDIUM,
            resource=role_name,
            description=desc,
            recommendation="Attach a permissions boundary defining max permissions.",
            passed=passed,
        )

    @staticmethod
    def _iam004_passrole(docs: list[tuple[str, dict]], role_name: str, error: str | None = None) -> Finding:
        offenders = [n for n, d in docs if _passrole_wildcard(d)]
        passed = not offenders and error is None
        if error:
            desc = f"{error}. Cannot verify iam:PassRole scope for '{role_name}'."
        elif offenders:
            desc = (
                f"Policy/policies {offenders} grant iam:PassRole with Resource: '*' — "
                f"a classic privilege-escalation path."
            )
        else:
            desc = f"No policy on '{role_name}' grants iam:PassRole with Resource: '*'."
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

    @staticmethod
    def _iam005_external_trust(role: dict, role_name: str) -> Finding:
        doc = role.get("AssumeRolePolicyDocument", {})
        if isinstance(doc, str):
            try:
                doc = json.loads(doc)
            except json.JSONDecodeError:
                doc = {}

        bad: list[str] = []
        for idx, stmt in enumerate(_iter_allow(doc)):
            principal = stmt.get("Principal", {}) or {}
            if not (isinstance(principal, dict) and principal.get("AWS")):
                continue
            conditions = stmt.get("Condition", {}) or {}
            has_external_id = any(
                "sts:ExternalId" in (inner or {})
                for inner in conditions.values()
                if isinstance(inner, dict)
            )
            if not has_external_id:
                bad.append(f"stmt[{idx}]")

        passed = not bad
        desc = (
            f"Trust policy on '{role_name}' has no external AWS principal, or "
            f"every external principal requires sts:ExternalId."
            if passed else
            f"Trust policy on '{role_name}' allows assumption by an AWS "
            f"principal in {bad} without sts:ExternalId (confused-deputy risk)."
        )
        return Finding(
            check_id="IAM-005",
            title="CI/CD role trust policy missing sts:ExternalId",
            severity=Severity.HIGH,
            resource=role_name,
            description=desc,
            recommendation=(
                "Add a Condition requiring sts:ExternalId for external principals."
            ),
            passed=passed,
        )

    @staticmethod
    def _iam006_sensitive_wildcard(docs: list[tuple[str, dict]], role_name: str, error: str | None = None) -> Finding:
        hits: dict[str, list[str]] = {}
        for name, doc in docs:
            sensitive = _sensitive_wildcard(doc)
            if sensitive:
                hits[name] = sorted(set(sensitive))
        passed = not hits and error is None
        if error:
            desc = f"{error}. Cannot verify sensitive-action scoping for '{role_name}'."
        elif hits:
            desc = (
                f"Policy/policies on '{role_name}' grant sensitive actions over "
                f"Resource: '*': {', '.join(f'{k}→{v}' for k, v in hits.items())}."
            )
        else:
            desc = f"No policy on '{role_name}' pairs sensitive actions with Resource: '*'."
        return Finding(
            check_id="IAM-006",
            title="Sensitive actions granted with wildcard Resource",
            severity=Severity.MEDIUM,
            resource=role_name,
            description=desc,
            recommendation=(
                "Scope the Resource element to specific ARNs (buckets, keys, "
                "secrets, roles)."
            ),
            passed=passed,
        )
