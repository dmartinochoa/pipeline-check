"""ADO-014 — pipeline should not embed long-lived AWS access keys."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps
from ._helpers import AWS_KEY_RE

RULE = Rule(
    id="ADO-014",
    title="AWS auth uses long-lived access keys",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-TOKEN-HYGIENE",),
    recommendation=(
        "Use workload identity federation or an Azure Key Vault task "
        "to inject short-lived AWS credentials at runtime. Remove "
        "static AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY from "
        "pipeline variables and task parameters."
    ),
    docs_note=(
        "Long-lived `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` "
        "values in pipeline variables or task inputs can't be rotated "
        "on a fine-grained schedule. Prefer OIDC or vault-based "
        "credential injection for cross-cloud access."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    static_keys = False
    # Scan top-level variables.
    for v in _walk_vars(doc.get("variables")):
        if AWS_KEY_RE.search(v):
            static_keys = True
    # Scan job-level variables and step env.
    for _, job in iter_jobs(doc):
        for v in _walk_vars(job.get("variables")):
            if AWS_KEY_RE.search(v):
                static_keys = True
        for _, step in iter_steps(job):
            env = step.get("env") or {}
            if isinstance(env, dict):
                for val in env.values():
                    if isinstance(val, str) and AWS_KEY_RE.search(val):
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
            "(AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY) in variables "
            "or task parameters."
        ),
        recommendation=RULE.recommendation, passed=False,
    )


def _walk_vars(variables: Any) -> list[str]:
    """Extract string values from ADO variables (mapping or list form)."""
    out: list[str] = []
    if isinstance(variables, dict):
        for v in variables.values():
            if isinstance(v, str):
                out.append(v)
            elif isinstance(v, dict) and isinstance(v.get("value"), str):
                out.append(v["value"])
    elif isinstance(variables, list):
        for entry in variables:
            if isinstance(entry, dict) and isinstance(entry.get("value"), str):
                out.append(entry["value"])
    return out
