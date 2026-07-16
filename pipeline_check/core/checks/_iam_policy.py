"""Shared IAM policy-document helpers used by AWS and Terraform IAM checks.

Policy documents are the same shape regardless of how they were fetched
(boto3 GetPolicyVersion vs Terraform plan JSON). Keeping the walk/filter
logic here prevents the two providers from drifting, e.g. a new
``iam:PassRole`` variant or a new sensitive service prefix only needs to
land in one place.
"""
from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

CICD_SERVICE_PRINCIPALS = {
    "codebuild.amazonaws.com",
    "codepipeline.amazonaws.com",
    "codedeploy.amazonaws.com",
}

ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"

# Suffix shared across all partitions; used for partition-tolerant matching.
_ADMIN_POLICY_SUFFIX = ":iam::aws:policy/AdministratorAccess"

SENSITIVE_ACTION_PREFIXES = (
    "s3:", "kms:", "secretsmanager:", "ssm:", "iam:", "sts:",
    "dynamodb:", "lambda:", "ec2:",
)


def as_list(v: object) -> list[Any]:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def parse_doc(raw: object) -> dict[str, Any]:
    """Return a policy document as a dict. Accepts dict, JSON string, or junk."""
    if not raw:
        return {}
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, (str, bytes, bytearray)):
        return {}
    try:
        loaded = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


def iter_statements(doc: dict[str, Any]) -> Iterable[dict[str, Any]]:
    """Yield each statement *dict* from a policy document.

    ``Statement`` can legally be a single dict or a list; be tolerant of
    ``None`` and of malformed entries that aren't dicts at all. Unlike
    :func:`iter_allow` this does not filter on ``Effect`` (trust-policy
    callers, e.g. deciding whether a role is CI/CD-scoped, want every
    statement, not just ``Allow`` ones).
    """
    stmts = doc.get("Statement") or []
    if isinstance(stmts, dict):
        stmts = [stmts]
    elif not isinstance(stmts, list):
        return
    for stmt in stmts:
        if isinstance(stmt, dict):
            yield stmt


def iter_allow(doc: dict[str, Any]) -> Iterable[dict[str, Any]]:
    for stmt in iter_statements(doc):
        if stmt.get("Effect") == "Allow":
            yield stmt


def has_wildcard_action(doc: dict[str, Any], ignore_constrained: bool = False) -> bool:
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


def passrole_wildcard(doc: dict[str, Any], ignore_constrained: bool = False) -> bool:
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
#: pin an audience and a subject prefix, otherwise any workflow in
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


def is_oidc_trust_stmt(stmt: dict[str, Any]) -> str | None:
    """Return the matched OIDC host if *stmt* is a Federated/OIDC trust.

    Only Allow statements with a ``Principal.Federated`` whose value
    contains one of :data:`OIDC_FEDERATION_HOSTS` qualify.
    """
    if stmt.get("Effect") != "Allow":
        return None
    principal = stmt.get("Principal")
    if not isinstance(principal, dict):
        # A bare ``Principal: "*"`` (string) or a list is a public/anonymous
        # trust, not a Federated OIDC one; treat it as a non-match rather
        # than crashing on ``.get``.
        return None
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


def oidc_audience_pinned(stmt: dict[str, Any]) -> bool:
    """Return True when *stmt* pins an audience condition (``...:aud``)."""
    conditions = stmt.get("Condition", {}) or {}
    for inner in conditions.values():
        if not isinstance(inner, dict):
            continue
        for key in inner:
            if isinstance(key, str) and key.lower().endswith(":aud"):
                return True
    return False


def github_repo_sub_too_broad(value: str) -> bool:
    """Return True when a GitHub Actions OIDC ``sub`` claim is broad
    enough that an untrusted workflow run can assume the role.

    GitHub subjects look like ``repo:<owner>/<repo>:<context>`` where the
    context is e.g. ``ref:refs/heads/main`` / ``environment:prod`` /
    ``pull_request``. A subject is too broad when:

    * the owner/repo segment is wildcarded (``repo:*`` or
      ``repo:<owner>/*``), so any repo in (or beyond) the org federates; or
    * the context segment is a bare ``*`` (any ref / environment) or
      ``pull_request``, so a fork PR (via ``pull_request_target``) mints
      the role's token.

    Non-``repo:`` subjects (GitLab, Terraform Cloud, ...) return False:
    only the GitHub claim shape is recognized here, so other IdPs keep
    the looser "any non-``*`` value is a pin" treatment.
    """
    if not isinstance(value, str) or not value.startswith("repo:"):
        return False
    owner, sep, context = value[len("repo:"):].partition(":")
    # Owner/repo wildcard: ``repo:*``, ``repo:org/*``, or a bare segment.
    if owner == "*" or owner.endswith("/*") or "/" not in owner:
        return True
    # Context wildcard or the fork-reachable ``pull_request`` context.
    return bool(sep) and context in {"*", "pull_request"}


def oidc_subject_pinned(stmt: dict[str, Any]) -> bool:
    """Return True when *stmt* pins a subject condition (``...:sub``) to a
    specific principal.

    A subject is NOT a pin when it is absent, a bare ``*``, or - for
    GitHub Actions ``repo:`` claims - wildcarded at the owner/repo segment
    (``repo:org/*``) or the context segment (``repo:org/repo:*`` /
    ``...:pull_request``). Any of those lets an untrusted workflow run,
    including a fork pull request, assume the role.
    """
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
            # StringLike with bare "*" trusts every subject.
            if op.lower() == "stringlike" and all(v == "*" for v in values):
                return False
            # GitHub ``repo:`` claims that wildcard the repo or the ref,
            # or trust the ``pull_request`` context, are not real pins.
            if any(github_repo_sub_too_broad(v) for v in values):
                return False
            return True
    return False


def principal_is_only_account_root(stmt: dict[str, Any]) -> bool:
    """Return True when *stmt*'s principal is exclusively the account root
    (``arn:*:iam::<acct>:root``).

    The default / AWS-recommended KMS key policy grants ``kms:*`` to the
    account root so IAM policies can govern key access. That baseline
    statement is not an over-broad grant, so wildcard-action checks
    (KMS-002) must skip it. A role whose ARN ends in ``:role/root`` does
    not match (it ends with ``/root``, not ``:root``).
    """
    principal = stmt.get("Principal")
    if not isinstance(principal, dict) or set(principal) - {"AWS"}:
        return False
    values = as_list(principal.get("AWS"))
    if not values:
        return False
    return all(isinstance(v, str) and v.endswith(":root") for v in values)


def public_principal(stmt: dict[str, Any]) -> bool:
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


def sensitive_wildcard(doc: dict[str, Any]) -> list[str]:
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
