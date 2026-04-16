"""GHA-005 — AWS auth should use OIDC, not long-lived access keys."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps


RULE = Rule(
    id="GHA-005",
    title="AWS auth uses long-lived access keys",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-TOKEN-HYGIENE",),
    recommendation=(
        "Use `aws-actions/configure-aws-credentials` with "
        "`role-to-assume` + `permissions: id-token: write` to obtain "
        "short-lived credentials via OIDC. Remove the static "
        "AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY secrets."
    ),
    docs_note=(
        "Long-lived `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` "
        "secrets in GitHub Actions can't be rotated on a fine-"
        "grained schedule and remain valid until manually revoked. "
        "OIDC with `role-to-assume` yields short-lived credentials "
        "per workflow run."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    static_keys = False
    oidc_role = False
    for _, job in iter_jobs(doc):
        for step in iter_steps(job):
            uses = step.get("uses") or ""
            if isinstance(uses, str) and uses.startswith(
                "aws-actions/configure-aws-credentials@"
            ):
                w = step.get("with") or {}
                if "role-to-assume" in w:
                    oidc_role = True
                if "aws-access-key-id" in w or "aws-secret-access-key" in w:
                    static_keys = True
            env = step.get("env") or {}
            if isinstance(env, dict):
                for value in env.values():
                    if isinstance(value, str) and (
                        "AWS_ACCESS_KEY_ID" in value
                        or "AWS_SECRET_ACCESS_KEY" in value
                    ):
                        static_keys = True
    doc_env = doc.get("env") or {}
    if isinstance(doc_env, dict):
        for value in doc_env.values():
            if isinstance(value, str) and (
                "AWS_ACCESS_KEY_ID" in value
                or "AWS_SECRET_ACCESS_KEY" in value
            ):
                static_keys = True
    if not static_keys and not oidc_role:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="Workflow does not configure AWS credentials.",
            recommendation="No action required.", passed=True,
        )
    passed = oidc_role and not static_keys
    if passed:
        desc = "AWS credentials are obtained via OIDC (`role-to-assume`)."
    elif static_keys:
        desc = (
            "Workflow authenticates to AWS with long-lived access keys "
            "(AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY). These can't be "
            "rotated on a fine-grained schedule and remain valid until "
            "manually revoked."
        )
    else:
        desc = "AWS credential configuration detected but could not be classified."
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
