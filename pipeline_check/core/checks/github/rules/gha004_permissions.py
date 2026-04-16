"""GHA-004 — workflow must declare an explicit `permissions:` block."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs


RULE = Rule(
    id="GHA-004",
    title="Workflow has no explicit permissions block",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-5",),
    esf=("ESF-C-LEAST-PRIV",),
    recommendation=(
        "Add a top-level `permissions:` block (start with `contents: "
        "read`) and grant additional scopes only on the specific jobs "
        "that need them."
    ),
    docs_note=(
        "Without an explicit `permissions:` block (either top-level "
        "or per-job), the GITHUB_TOKEN inherits the repository's "
        "default scope — typically `write`. A compromised step "
        "receives far more privilege than it needs."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    if "permissions" in doc:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="Workflow declares a top-level permissions block.",
            recommendation="No action required.", passed=True,
        )
    jobs_missing = [
        job_id for job_id, job in iter_jobs(doc) if "permissions" not in job
    ]
    passed = not jobs_missing
    desc = (
        "Every job declares its own permissions block."
        if passed else
        f"Workflow has no top-level permissions block and "
        f"{len(jobs_missing)} job(s) without a per-job permissions "
        f"block: {', '.join(jobs_missing)}. The GITHUB_TOKEN will "
        f"default to repository-wide scope, giving any compromised "
        f"step more privilege than necessary."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
