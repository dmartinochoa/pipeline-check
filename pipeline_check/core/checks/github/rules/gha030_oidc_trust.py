"""GHA-030. OIDC token requested without environment-protected job."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps

#: ``uses:`` prefixes that exchange the GHA OIDC token for cloud
#: credentials. A job that invokes any of these without an attached
#: ``environment:`` is unprotected, any branch with push access (or
#: a fork PR, depending on the trigger) can drive the role assumption.
_OIDC_CRED_STEPS = (
    "aws-actions/configure-aws-credentials",
    "azure/login",
    "google-github-actions/auth",
)


def _job_has_id_token(job: dict[str, Any], workflow: dict[str, Any]) -> bool:
    """Return True if *job* effectively has ``id-token: write``.

    GitHub's permission semantics: a job-level ``permissions:`` block
    REPLACES the workflow-level block (it does not merge). Without a
    job-level block, the job inherits the workflow's permissions; with
    one, only the keys the job declares apply.
    """
    job_perms = job.get("permissions")
    if isinstance(job_perms, dict):
        return job_perms.get("id-token") == "write"
    if isinstance(job_perms, str):
        return job_perms == "write-all"
    wf_perms = workflow.get("permissions")
    if isinstance(wf_perms, dict):
        return wf_perms.get("id-token") == "write"
    if isinstance(wf_perms, str):
        return wf_perms == "write-all"
    return False


def _job_invokes_oidc_step(job: dict[str, Any]) -> bool:
    """Return True if any step uses an OIDC cloud-credentials action."""
    for step in iter_steps(job):
        uses = step.get("uses")
        if not isinstance(uses, str):
            continue
        action = uses.split("@", 1)[0]
        if any(action.startswith(prefix) for prefix in _OIDC_CRED_STEPS):
            return True
    return False


RULE = Rule(
    id="GHA-030",
    title="OIDC token requested without environment-protected job",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-284",),
    recommendation=(
        "Bind every job that exchanges the GHA OIDC token for cloud "
        "credentials to a protected ``environment:`` (e.g. "
        "``environment: production``). Environment protections layer "
        "in branch restrictions, required reviewers, and deployment "
        "windows that the IdP-side trust policy cannot enforce alone."
    ),
    docs_note=(
        "Pairs with IAM-008. IAM-008 verifies the AWS-side trust "
        "policy pins audience + subject; this rule verifies the "
        "GitHub-side workflow can't request the token from any "
        "branch without a deployment gate. A misconfiguration on "
        "either side defeats the OIDC story."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for job_id, job in iter_jobs(doc):
        if not _job_has_id_token(job, doc):
            continue
        if not _job_invokes_oidc_step(job):
            continue
        if "environment" in job:
            continue
        offenders.append(job_id)
    passed = not offenders
    desc = (
        "Every job that requests an OIDC token to assume a cloud role "
        "is bound to a protected environment."
        if passed else
        f"Job(s) {', '.join(offenders)} request ``id-token: write`` and "
        f"invoke a cloud-credentials action (configure-aws-credentials, "
        f"azure/login, or google-github-actions/auth) without an "
        f"``environment:`` binding. Without an environment, branch "
        f"protections and required reviewers don't gate the role "
        f"assumption."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
