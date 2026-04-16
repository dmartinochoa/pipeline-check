"""GHA-015 — every job should declare `timeout-minutes`."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs

RULE = Rule(
    id="GHA-015",
    title="Job has no `timeout-minutes` — unbounded build",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-BUILD-TIMEOUT",),
    cwe=("CWE-400",),
    recommendation=(
        "Add `timeout-minutes:` to each job, sized to the 95th "
        "percentile of historical runtime plus margin. GitHub's "
        "default is 360 minutes — an explicitly shorter value limits "
        "blast radius and runner cost."
    ),
    docs_note=(
        "Without `timeout-minutes`, the job runs until GitHub's "
        "6-hour default kills it. Explicit timeouts cap blast radius, "
        "cost, and the window during which a compromised step has "
        "access to secrets."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    unbounded: list[str] = []
    for job_id, job in iter_jobs(doc):
        if "timeout-minutes" not in job:
            unbounded.append(job_id)
    passed = not unbounded
    desc = (
        "Every job declares a `timeout-minutes`."
        if passed else
        f"{len(unbounded)} job(s) have no `timeout-minutes` and will "
        f"run until GitHub's 360-minute default: "
        f"{', '.join(unbounded[:5])}{'…' if len(unbounded) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
