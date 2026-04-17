"""CC-014 — jobs should specify a resource_class to limit executor scope."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs

RULE = Rule(
    id="CC-014",
    title="Job missing `resource_class` declaration",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-5",),
    esf=("ESF-D-BUILD-ENV",),
    cwe=("CWE-250",),
    recommendation=(
        "Add `resource_class:` to every job to explicitly control the "
        "executor size and capabilities. Use the smallest class that "
        "satisfies build requirements."
    ),
    docs_note=(
        "Without an explicit `resource_class`, CircleCI assigns a "
        "default executor. Declaring the class documents the expected "
        "scope and prevents accidental use of larger (or self-hosted) "
        "executors that may have elevated privileges."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    missing: list[str] = []
    for job_id, job in iter_jobs(doc):
        if "resource_class" not in job:
            missing.append(job_id)
    passed = not missing
    desc = (
        "All jobs declare a `resource_class`, or no jobs exist."
        if passed else
        f"{len(missing)} job(s) missing `resource_class`: "
        f"{', '.join(missing[:5])}"
        f"{'...' if len(missing) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
