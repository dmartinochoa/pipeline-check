"""ADO-015 — every job should declare `timeoutInMinutes`."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs

RULE = Rule(
    id="ADO-015",
    title="Job has no `timeoutInMinutes` — unbounded build",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-BUILD-TIMEOUT",),
    recommendation=(
        "Add `timeoutInMinutes:` to each job, sized to the 95th "
        "percentile of historical runtime plus margin. Azure's "
        "default is 60 minutes — an explicitly shorter value limits "
        "blast radius and agent cost."
    ),
    docs_note=(
        "Without `timeoutInMinutes`, the job runs until Azure's "
        "60-minute default kills it. Explicit timeouts cap blast "
        "radius and the window during which a compromised step has "
        "access to service connections."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    unbounded: list[str] = []
    for job_loc, job in iter_jobs(doc):
        if "timeoutInMinutes" not in job:
            unbounded.append(job_loc)
    passed = not unbounded
    desc = (
        "Every job declares a `timeoutInMinutes`."
        if passed else
        f"{len(unbounded)} job(s) have no `timeoutInMinutes`: "
        f"{', '.join(unbounded[:5])}{'…' if len(unbounded) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
