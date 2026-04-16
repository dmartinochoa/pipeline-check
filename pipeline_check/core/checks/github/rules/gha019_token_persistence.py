"""GHA-019 — GITHUB_TOKEN written to persistent storage."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps

_TOKEN_PERSIST_RE = re.compile(
    r"GITHUB_TOKEN.*(?:>>?\s|tee\s)"
    r"|>>?\s*\$GITHUB_ENV.*GITHUB_TOKEN"
    r"|\$\{\{\s*secrets\.GITHUB_TOKEN\s*\}\}.*>>?"
)

RULE = Rule(
    id="GHA-019",
    title="GITHUB_TOKEN written to persistent storage",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    recommendation=(
        "Never write GITHUB_TOKEN to files, artifacts, or GITHUB_ENV. "
        "Use the token inline via ${{ secrets.GITHUB_TOKEN }} in the "
        "step that needs it."
    ),
    docs_note=(
        "Detects patterns where `GITHUB_TOKEN` is written to files, "
        "environment files (`$GITHUB_ENV`), or piped through `tee`. "
        "Persisted tokens survive the step boundary and can be "
        "exfiltrated by later steps, uploaded artifacts, or cache "
        "entries — turning a scoped credential into a long-lived one."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for job_id, job in iter_jobs(doc):
        for step in iter_steps(job):
            run = step.get("run")
            if not isinstance(run, str):
                continue
            if _TOKEN_PERSIST_RE.search(run):
                name = step.get("name") or step.get("id") or "unnamed"
                offenders.append(f"{job_id}.{name}")
    passed = not offenders
    desc = (
        "No GITHUB_TOKEN persistence patterns detected in this workflow."
        if passed else
        f"GITHUB_TOKEN written to persistent storage in: "
        f"{', '.join(offenders[:5])}"
        f"{'...' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
