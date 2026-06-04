"""IAM-008. OIDC-federated role trust policy missing audience/subject pin."""
from __future__ import annotations

import json
from typing import Any

from ..._iam_policy import (
    is_oidc_trust_stmt,
    oidc_audience_pinned,
    oidc_subject_pinned,
)
from ...base import Finding, Severity
from ...rule import Rule
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
        "(``...:aud = sts.amazonaws.com``) and a specific subject "
        "(``...:sub`` matching one repo AND ref, e.g. "
        "``repo:myorg/myrepo:ref:refs/heads/main`` or "
        "``...:environment:production``). An org wildcard "
        "(``repo:myorg/*``), a ref wildcard (``repo:myorg/myrepo:*``), or "
        "the ``pull_request`` context all let an untrusted workflow run "
        "(including a fork PR) assume the role."
    ),
    docs_note=(
        "IAM-005 already covers cross-account AWS principals. This rule "
        "targets the OIDC federation path specifically because the blast "
        "radius of a missed audience/subject pin is the entire identity "
        "provider's tenant base (e.g. all GitHub users, not just your "
        "org). For GitHub ``repo:`` subjects it also fires when the "
        "subject is present but wildcards the repo or ref segment, or "
        "trusts the ``pull_request`` context, since a fork PR then mints "
        "the role's token."
    ),
    exploit_example=(
        "# Vulnerable: an OIDC-federated IAM role's trust policy\n"
        "# is missing either the audience (``:aud``) check or\n"
        "# the subject (``:sub``) pin. Any OIDC token from the\n"
        "# named provider — even one minted for a different\n"
        "# audience or a different repo / branch — can assume\n"
        "# the role.\n"
        "{\n"
        "  \"Statement\": [{\n"
        "    \"Effect\": \"Allow\",\n"
        "    \"Principal\": {\"Federated\":\n"
        "      \"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com\"},\n"
        "    \"Action\": \"sts:AssumeRoleWithWebIdentity\"\n"
        "    // no Condition\n"
        "  }]\n"
        "}\n"
        "\n"
        "# Safe: pin BOTH ``:aud`` (the audience the token was\n"
        "# minted for, typically ``sts.amazonaws.com``) AND\n"
        "# ``:sub`` (the specific repo + branch / environment).\n"
        "# Reject any token whose claims don't match.\n"
        "{\n"
        "  \"Statement\": [{\n"
        "    \"Effect\": \"Allow\",\n"
        "    \"Principal\": {\"Federated\":\n"
        "      \"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com\"},\n"
        "    \"Action\": \"sts:AssumeRoleWithWebIdentity\",\n"
        "    \"Condition\": {\n"
        "      \"StringEquals\": {\n"
        "        \"token.actions.githubusercontent.com:aud\": \"sts.amazonaws.com\",\n"
        "        \"token.actions.githubusercontent.com:sub\":\n"
        "          \"repo:myorg/myrepo:environment:production\"\n"
        "      }\n"
        "    }\n"
        "  }]\n"
        "}"
    ),
)


def _parse(doc: object) -> dict[str, Any]:
    if isinstance(doc, dict):
        return doc
    if isinstance(doc, str):
        try:
            parsed = json.loads(doc)
            return parsed if isinstance(parsed, dict) else {}
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
                offending.append(f"stmt[{idx}]({host}): :sub missing or too broad")
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
