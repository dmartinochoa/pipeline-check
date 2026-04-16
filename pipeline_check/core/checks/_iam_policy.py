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


def has_wildcard_action(doc: dict) -> bool:
    for stmt in iter_allow(doc):
        if "*" in as_list(stmt.get("Action")):
            return True
    return False


def passrole_wildcard(doc: dict) -> bool:
    for stmt in iter_allow(doc):
        actions = as_list(stmt.get("Action"))
        if not any(a in ("iam:PassRole", "iam:*", "*") for a in actions):
            continue
        if "*" in as_list(stmt.get("Resource")):
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
