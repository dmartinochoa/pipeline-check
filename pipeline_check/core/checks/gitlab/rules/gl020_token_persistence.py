"""GL-020 — CI_JOB_TOKEN written to persistent storage."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, job_scripts

_TOKEN_PERSIST_RE = re.compile(
    r"CI_JOB_TOKEN.*(?:>>?\s|tee\s)"
    r"|>>?\s*.*CI_JOB_TOKEN"
    r"|\$CI_JOB_TOKEN.*>>?"
)

RULE = Rule(
    id="GL-020",
    title="CI_JOB_TOKEN written to persistent storage",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    recommendation=(
        "Never write CI_JOB_TOKEN to files, artifacts, or dotenv reports. "
        "Use the token inline in the command that needs it and let GitLab "
        "revoke it automatically when the job finishes."
    ),
    docs_note=(
        "Detects patterns where `CI_JOB_TOKEN` is redirected to a file, "
        "piped through `tee`, or appended to dotenv/artifact paths. "
        "Persisted tokens survive the job boundary and can be read by "
        "later stages, downloaded artifacts, or cache entries — turning "
        "a scoped credential into a long-lived one."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for job_id, job in iter_jobs(doc):
        for line in job_scripts(job):
            if _TOKEN_PERSIST_RE.search(line):
                offenders.append(job_id)
                break
    passed = not offenders
    desc = (
        "No CI_JOB_TOKEN persistence patterns detected in this pipeline."
        if passed
        else f"CI_JOB_TOKEN written to persistent storage in: "
        f"{', '.join(offenders[:5])}"
        f"{'...' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id,
        title=RULE.title,
        severity=RULE.severity,
        resource=path,
        description=desc,
        recommendation=RULE.recommendation,
        passed=passed,
    )
