"""Shared IAM role/policy enumeration for the IAM-* Terraform rules.

The IAM rules all operate on the same indexed view of the plan:

  - CI/CD-scoped roles (assume_role_policy trusts CodeBuild / CodePipeline
    / CodeDeploy)
  - the union of every policy document reachable from each role (inline,
    attached, managed)

Computing that view once per rule is wasteful — and putting it in a
shared helper keeps each rule's ``check(ctx)`` short. This module is
underscore-prefixed so :func:`discover_rules` skips it.
"""
from __future__ import annotations

from typing import Any

from ..._iam_policy import (
    CICD_SERVICE_PRINCIPALS as _CICD_SERVICE_PRINCIPALS,
)
from ..._iam_policy import (
    iter_statements as _iter_statements,
)
from ..._iam_policy import (
    parse_doc as _parse,
)
from ..base import TerraformContext, TerraformResource


def _role_is_cicd(values: dict[str, Any]) -> bool:
    doc = _parse(values.get("assume_role_policy"))
    for stmt in _iter_statements(doc):
        principal = stmt.get("Principal")
        if not isinstance(principal, dict):
            # A string ``Principal: "*"`` (public trust) or a list can't
            # name a CI/CD service principal, so skip instead of crashing.
            continue
        services = principal.get("Service", [])
        if isinstance(services, str):
            services = [services]
        if not isinstance(services, list):
            continue
        if any(s in _CICD_SERVICE_PRINCIPALS for s in services):
            return True
    return False


def cicd_role_view(
    ctx: TerraformContext,
) -> list[tuple[TerraformResource, list[str], list[tuple[str, dict[str, Any]]]]]:
    """Return ``[(role, managed_arns, policy_docs), …]`` for every CI/CD role.

    ``policy_docs`` is a list of ``(name, parsed_policy_doc)`` for every
    policy document reachable from the role: inline ``aws_iam_role_policy``
    records, inline blocks on the role itself, and customer-managed
    ``aws_iam_policy`` records joined through
    ``aws_iam_role_policy_attachment``.
    """
    cicd_roles: list[TerraformResource] = [
        r for r in ctx.resources("aws_iam_role") if _role_is_cicd(r.values)
    ]
    if not cicd_roles:
        return []

    attachments: dict[str, list[str]] = {}
    for r in ctx.resources("aws_iam_role_policy_attachment"):
        role = r.values.get("role", "")
        arn = r.values.get("policy_arn", "")
        if role and arn:
            attachments.setdefault(role, []).append(arn)

    inline_separate: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    for r in ctx.resources("aws_iam_role_policy"):
        role = r.values.get("role", "")
        if not role:
            continue
        pname = r.values.get("name") or r.name
        doc = _parse(r.values.get("policy"))
        inline_separate.setdefault(role, []).append((pname, doc))

    customer_policies_by_arn: dict[str, dict[str, Any]] = {}
    for r in ctx.resources("aws_iam_policy"):
        doc = _parse(r.values.get("policy"))
        arn = r.values.get("arn")
        if arn:
            customer_policies_by_arn[arn] = doc

    out: list[
        tuple[TerraformResource, list[str], list[tuple[str, dict[str, Any]]]]
    ] = []
    for r in cicd_roles:
        role_name = r.values.get("name") or r.name
        managed_arns: list[str] = list(r.values.get("managed_policy_arns") or [])
        managed_arns.extend(attachments.get(role_name, []))
        policy_docs: list[tuple[str, dict[str, Any]]] = []
        policy_docs.extend(inline_separate.get(role_name, []))
        for block in (r.values.get("inline_policy") or []):
            policy_docs.append(
                (block.get("name", "inline"), _parse(block.get("policy")))
            )
        for arn in managed_arns:
            if arn in customer_policies_by_arn:
                policy_docs.append((arn, customer_policies_by_arn[arn]))
        out.append((r, managed_arns, policy_docs))
    return out
