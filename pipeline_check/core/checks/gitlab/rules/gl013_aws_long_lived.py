"""GL-013 — pipeline should not embed long-lived AWS access keys."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs
from ._helpers import AWS_KEY_RE

RULE = Rule(
    id="GL-013",
    title="AWS auth uses long-lived access keys",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-TOKEN-HYGIENE",),
    recommendation=(
        "Use GitLab CI/CD OIDC with `id_tokens:` to obtain short-lived "
        "AWS credentials via `sts:AssumeRoleWithWebIdentity`. Remove "
        "static AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY from CI/CD "
        "variables."
    ),
    docs_note=(
        "Long-lived `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` "
        "values in CI/CD variables can't be rotated on a fine-grained "
        "schedule. GitLab supports OIDC via `id_tokens:` for short-"
        "lived credential injection."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    static_keys = False
    # Scan top-level variables.
    top_vars = doc.get("variables") or {}
    if isinstance(top_vars, dict):
        for v in top_vars.values():
            if isinstance(v, str) and AWS_KEY_RE.search(v):
                static_keys = True
    # Scan per-job variables.
    for _, job in iter_jobs(doc):
        job_vars = job.get("variables") or {}
        if isinstance(job_vars, dict):
            for v in job_vars.values():
                if isinstance(v, str) and AWS_KEY_RE.search(v):
                    static_keys = True
    if not static_keys:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="Pipeline does not reference long-lived AWS keys.",
            recommendation="No action required.", passed=True,
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path,
        description=(
            "Pipeline references long-lived AWS access keys "
            "(AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY) in CI/CD "
            "variables."
        ),
        recommendation=RULE.recommendation, passed=False,
    )
