"""ADO-004 — deployment jobs must bind an environment."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs


RULE = Rule(
    id="ADO-004",
    title="Deployment job missing environment binding",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-1",),
    esf=("ESF-C-APPROVAL", "ESF-C-ENV-SEP"),
    recommendation=(
        "Add `environment: <name>` to every `deployment:` job. "
        "Configure approvals, required branches, and business-hours "
        "checks on the matching Environment in the ADO UI."
    ),
    docs_note=(
        "Without an `environment:` binding, ADO cannot enforce "
        "approvals, checks, or deployment history against a named "
        "resource. Every `deployment:` job should bind one."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    ungated: list[str] = []
    for job_loc, job in iter_jobs(doc):
        if not isinstance(job.get("deployment"), str):
            continue
        if not job.get("environment"):
            ungated.append(job_loc)
    passed = not ungated
    desc = (
        "Every deployment job binds an `environment`."
        if passed else
        f"{len(ungated)} deployment job(s) have no `environment:` "
        f"binding: {', '.join(ungated)}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
