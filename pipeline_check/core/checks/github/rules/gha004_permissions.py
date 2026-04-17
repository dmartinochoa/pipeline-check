"""GHA-004 — workflow must declare an explicit `permissions:` block."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps, workflow_triggers

RULE = Rule(
    id="GHA-004",
    title="Workflow has no explicit permissions block",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-5",),
    esf=("ESF-C-LEAST-PRIV",),
    cwe=("CWE-250",),
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
    known_fp=(
        "Read-only / lint-only workflows that do not call any "
        "write-scoped API often pass without an explicit block "
        "because the default token scope on public repos is read. "
        "The rule defaults to MEDIUM confidence to reflect this.",
    ),
)


def _is_write_all(perms: Any) -> bool:
    """True if permissions is the string ``write-all``."""
    return isinstance(perms, str) and perms.strip().lower() == "write-all"


def _perms_issues(
    perms: Any, job_id: str, triggers: list[str],
    job: dict[str, Any] | None = None,
) -> list[str]:
    """Return human-readable issues with a permissions block."""
    issues: list[str] = []
    if _is_write_all(perms):
        issues.append(f"{job_id}: `permissions: write-all` is overly broad")
    if isinstance(perms, dict):
        # contents: write on a PR-triggered workflow is suspicious
        pr_triggers = {"pull_request", "pull_request_target"}
        if perms.get("contents") == "write" and pr_triggers & set(triggers):
            issues.append(
                f"{job_id}: `contents: write` on a pull_request workflow"
            )
        # id-token: write without a corresponding OIDC step
        if perms.get("id-token") == "write" and job is not None:
            has_oidc = any(
                isinstance(s.get("uses"), str)
                and "configure-aws-credentials" in s["uses"]
                and "role-to-assume" in (s.get("with") or {})
                for s in iter_steps(job)
            )
            if not has_oidc:
                issues.append(
                    f"{job_id}: `id-token: write` with no OIDC step"
                )
    return issues


def check(path: str, doc: dict[str, Any]) -> Finding:
    triggers = workflow_triggers(doc)
    issues: list[str] = []

    # Check top-level permissions.
    top_perms = doc.get("permissions")
    if top_perms is not None:
        issues.extend(_perms_issues(top_perms, "<workflow>", triggers))

    # Check per-job permissions.
    jobs_missing: list[str] = []
    for job_id, job in iter_jobs(doc):
        job_perms = job.get("permissions")
        if job_perms is not None:
            issues.extend(
                _perms_issues(job_perms, job_id, triggers, job=job)
            )
        elif top_perms is None:
            jobs_missing.append(job_id)

    if jobs_missing:
        issues.append(
            f"{len(jobs_missing)} job(s) without permissions: "
            f"{', '.join(jobs_missing)}"
        )

    passed = not issues
    if passed:
        desc = (
            "Workflow declares a permissions block with no overly broad grants."
        )
    else:
        desc = (
            f"Permissions issues detected: {'; '.join(issues)}. "
            f"The GITHUB_TOKEN may have more privilege than necessary."
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
