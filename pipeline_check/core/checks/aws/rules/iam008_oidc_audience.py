"""IAM-008 — OIDC-federated role trust policy missing audience/subject pin."""
from __future__ import annotations

import json

from ...base import Finding, Severity
from ...rule import Rule
from ..._iam_policy import (
    is_oidc_trust_stmt,
    oidc_audience_pinned,
    oidc_subject_pinned,
)
from .._catalog import ResourceCatalog

RULE = Rule(
    id="IAM-008",
    title="OIDC-federated role trust policy missing audience or subject pin",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-284",),
    recommendation=(
        "Every Allow statement that trusts a federated OIDC provider "
        "(``token.actions.githubusercontent.com``, GitLab, CircleCI, "
        "Terraform Cloud, etc.) must pin both the audience "
        "(``...:aud = sts.amazonaws.com``) and a subject prefix "
        "(``...:sub`` matching ``repo:myorg/*``). Without these, any "
        "workflow from any tenant can assume the role."
    ),
    docs_note=(
        "IAM-005 already covers cross-account AWS principals. This rule "
        "targets the OIDC federation path specifically because the blast "
        "radius of a missed audience/subject pin is the entire identity "
        "provider's tenant base (e.g. all GitHub users, not just your org)."
    ),
)


def _parse(doc):
    if isinstance(doc, dict):
        return doc
    if isinstance(doc, str):
        try:
            return json.loads(doc)
        except json.JSONDecodeError:
            return {}
    return {}


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for role in catalog.iam_roles():
        role_name = role.get("RoleName", "<unnamed>")
        doc = _parse(role.get("AssumeRolePolicyDocument"))
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
        passed = not offending
        if passed:
            desc = (
                f"Role '{role_name}' OIDC trust policy pins both audience and "
                "subject on every federated statement."
            )
        else:
            desc = (
                f"Role '{role_name}' OIDC trust policy is under-scoped: "
                f"{'; '.join(offending)}. Any tenant of the IdP can assume "
                "this role."
            )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=role_name, description=desc,
            recommendation=RULE.recommendation, passed=passed,
        ))
    return findings
