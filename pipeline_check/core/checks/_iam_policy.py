"""Shared IAM policy-document helpers used by AWS and Terraform IAM checks.

Policy documents are the same shape regardless of how they were fetched
(boto3 GetPolicyVersion vs Terraform plan JSON). Keeping the walk/filter
logic here prevents the two providers from drifting — e.g. a new
``iam:PassRole`` variant or a new sensitive service prefix only needs to
land in one place.
"""
from __future__ import annotations

import json
from collections.abc import Iterable

CICD_SERVICE_PRINCIPALS = {
    "codebuild.amazonaws.com",
    "codepipeline.amazonaws.com",
    "codedeploy.amazonaws.com",
}

ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"

SENSITIVE_ACTION_PREFIXES = (
    "s3:", "kms:", "secretsmanager:", "ssm:", "iam:", "sts:",
    "dynamodb:", "lambda:", "ec2:",
)


def as_list(v) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def parse_doc(raw) -> dict:
    """Return a policy document as a dict. Accepts dict, JSON string, or junk."""
    if not raw:
        return {}
    if isinstance(raw, dict):
        return raw
    try:
        return json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return {}


def iter_allow(doc: dict) -> Iterable[dict]:
    # Statement can legally be a single dict or a list; be tolerant of None
    # and of malformed entries that aren't dicts at all.
    stmts = doc.get("Statement") or []
    if isinstance(stmts, dict):
        stmts = [stmts]
    elif not isinstance(stmts, list):
        return
    for stmt in stmts:
        if isinstance(stmt, dict) and stmt.get("Effect") == "Allow":
            yield stmt


def has_wildcard_action(doc: dict, ignore_constrained: bool = False) -> bool:
    """Return True when any ``Allow`` statement has ``Action: "*"``.

    When *ignore_constrained* is True, statements that carry a
    narrowing ``Condition`` block (``aws:SourceAccount``,
    ``aws:PrincipalOrgID``, ``aws:PrincipalTag``, etc.) are skipped —
    a wildcard action under a strong condition is not the same risk
    as a bare wildcard.
    """
    from ._context import statement_is_constrained  # local import to avoid cycle
    for stmt in iter_allow(doc):
        if "*" not in as_list(stmt.get("Action")):
            continue
        if ignore_constrained and statement_is_constrained(stmt):
            continue
        return True
    return False


def passrole_wildcard(doc: dict, ignore_constrained: bool = False) -> bool:
    from ._context import statement_is_constrained
    for stmt in iter_allow(doc):
        actions = as_list(stmt.get("Action"))
        if not any(a in ("iam:PassRole", "iam:*", "*") for a in actions):
            continue
        if "*" not in as_list(stmt.get("Resource")):
            continue
        if ignore_constrained and statement_is_constrained(stmt):
            continue
        return True
    return False


#: Tokens suggesting an OIDC identity-provider federation (GitHub
#: Actions, GitLab CI, Terraform Cloud, BuildKite, CircleCI, Bitbucket,
#: Azure DevOps). Trust statements referencing any of these must also
#: pin an audience and a subject prefix — otherwise any workflow in
#: any GitHub org can assume the role.
OIDC_FEDERATION_HOSTS = (
    "token.actions.githubusercontent.com",
    "gitlab.com",                          # id_tokens
    "app.terraform.io",
    "agent.buildkite.com",
    "oidc.circleci.com",
    "api.bitbucket.org",
    "vstoken.dev.azure.com",
)


def is_oidc_trust_stmt(stmt: dict) -> str | None:
    """Return the matched OIDC host if *stmt* is a Federated/OIDC trust.

    Only Allow statements with a ``Principal.Federated`` whose value
    contains one of :data:`OIDC_FEDERATION_HOSTS` qualify.
    """
    if stmt.get("Effect") != "Allow":
        return None
    principal = stmt.get("Principal", {}) or {}
    federated = principal.get("Federated")
    if not federated:
        return None
    values = as_list(federated)
    for v in values:
        if not isinstance(v, str):
            continue
        for host in OIDC_FEDERATION_HOSTS:
            if host in v:
                return host
    return None


def oidc_audience_pinned(stmt: dict) -> bool:
    """Return True when *stmt* pins an audience condition (``...:aud``)."""
    conditions = stmt.get("Condition", {}) or {}
    for inner in conditions.values():
        if not isinstance(inner, dict):
            continue
        for key in inner:
            if isinstance(key, str) and key.lower().endswith(":aud"):
                return True
    return False


def oidc_subject_pinned(stmt: dict) -> bool:
    """Return True when *stmt* pins a subject condition (``...:sub``)
    **and** the value is not an unrestricted wildcard."""
    conditions = stmt.get("Condition", {}) or {}
    for op, inner in conditions.items():
        if not isinstance(inner, dict):
            continue
        for key, value in inner.items():
            if not (isinstance(key, str) and key.lower().endswith(":sub")):
                continue
            values = as_list(value)
            if not values:
                return False
            # StringLike with bare "*" defeats the purpose. Any other
            # pattern (including ``repo:myorg/*:ref:refs/heads/main``)
            # is considered pinned.
            if op.lower() == "stringlike" and all(v == "*" for v in values):
                return False
            return True
    return False


def public_principal(stmt: dict) -> bool:
    """Return True when *stmt* grants access to an anonymous / wildcard principal."""
    if stmt.get("Effect") != "Allow":
        return False
    principal = stmt.get("Principal")
    if principal == "*":
        return True
    if isinstance(principal, dict):
        for v in principal.values():
            if v == "*" or (isinstance(v, list) and "*" in v):
                return True
    return False


def sensitive_wildcard(doc: dict) -> list[str]:
    """Actions paired with Resource:"*" that fall under a sensitive prefix.

    IAM-002 handles Action:"*" directly, so it is filtered out here to avoid
    double-reporting.
    """
    hits: list[str] = []
    for stmt in iter_allow(doc):
        actions = as_list(stmt.get("Action"))
        if "*" in actions:
            continue
        if "*" not in as_list(stmt.get("Resource")):
            continue
        for a in actions:
            if isinstance(a, str) and a.startswith(SENSITIVE_ACTION_PREFIXES):
                hits.append(a)
    return hits
