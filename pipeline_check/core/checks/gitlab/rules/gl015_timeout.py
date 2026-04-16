"""GL-015 — every job should declare a `timeout`."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs

RULE = Rule(
    id="GL-015",
    title="Job has no `timeout` — unbounded build",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-BUILD-TIMEOUT",),
    recommendation=(
        "Add `timeout:` to each job (e.g. `timeout: 30 minutes`), "
        "sized to the 95th percentile of historical runtime. GitLab's "
        "default is 60 minutes (or the instance admin setting)."
    ),
    docs_note=(
        "Without an explicit `timeout`, the job runs until the "
        "instance-level default (typically 60 minutes). Explicit "
        "timeouts cap blast radius and the window during which a "
        "compromised script has access to CI/CD variables."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    unbounded: list[str] = []
    for name, job in iter_jobs(doc):
        if "timeout" not in job:
            unbounded.append(name)
    passed = not unbounded
    desc = (
        "Every job declares a `timeout`."
        if passed else
        f"{len(unbounded)} job(s) have no `timeout`: "
        f"{', '.join(unbounded[:5])}{'…' if len(unbounded) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
