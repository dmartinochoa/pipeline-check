"""Shared IAM role/policy enumeration for the IAM-* CloudFormation rules.

The IAM rules all operate on the same indexed view of the template:

  - CI/CD-scoped roles (AssumeRolePolicyDocument trusts CodeBuild /
    CodePipeline / CodeDeploy)
  - the union of every policy document reachable from each role
    (inline ``Policies``, ``ManagedPolicyArns`` resolved against
    in-template ``AWS::IAM::ManagedPolicy`` resources)

Computing that view once per rule is wasteful; this helper does it
once and returns ``(role, managed_arns, policy_docs)`` triples.
Underscore-prefixed so :func:`discover_rules` skips it.
"""
from __future__ import annotations

from typing import Any

from ..._iam_policy import (
    CICD_SERVICE_PRINCIPALS as _CICD_SERVICE_PRINCIPALS,
)
from ..base import CloudFormationContext, CloudFormationResource, as_str


def _role_is_cicd(properties: dict[str, Any]) -> bool:
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


def cicd_role_view(
    ctx: CloudFormationContext,
) -> list[tuple[CloudFormationResource, list[Any], list[tuple[str, dict[str, Any]]]]]:
    """Return ``[(role, managed_arns, policy_docs), …]`` for every CI/CD role."""
    cicd_roles: list[CloudFormationResource] = [
        r for r in ctx.resources("AWS::IAM::Role")
        if _role_is_cicd(r.properties)
    ]
    if not cicd_roles:
        return []

    managed_by_logical_id: dict[str, dict[str, Any]] = {}
    for r in ctx.resources("AWS::IAM::ManagedPolicy"):
        doc = r.properties.get("PolicyDocument")
        if isinstance(doc, dict):
            managed_by_logical_id[r.logical_id] = doc

    out: list[
        tuple[CloudFormationResource, list[Any], list[tuple[str, dict[str, Any]]]]
    ] = []
    for r in cicd_roles:
        role_name = as_str(r.properties.get("RoleName")) or r.logical_id
        del role_name  # used by callers via r.properties / r.logical_id
        arns = list(r.properties.get("ManagedPolicyArns") or [])
        policy_docs: list[tuple[str, dict[str, Any]]] = []
        for inline in (r.properties.get("Policies") or []):
            if not isinstance(inline, dict):
                continue
            pname = as_str(inline.get("PolicyName")) or "inline"
            doc = inline.get("PolicyDocument")
            if isinstance(doc, dict):
                policy_docs.append((pname, doc))
        for entry in arns:
            if isinstance(entry, dict) and "Ref" in entry:
                target = entry["Ref"]
                doc = managed_by_logical_id.get(target)
                if doc:
                    policy_docs.append((target, doc))
        out.append((r, arns, policy_docs))
    return out
