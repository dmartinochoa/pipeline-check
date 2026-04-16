"""CC-011 — Jobs should archive test results for traceability."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps

RULE = Rule(
    id="CC-011",
    title="No store_test_results step (test results not archived)",
    severity=Severity.LOW,
    owasp=("CICD-SEC-10",),
    esf=("ESF-C-AUDIT",),
    cwe=("CWE-532",),
    recommendation=(
        "Add a `store_test_results` step to jobs that run tests. This "
        "archives test results in CircleCI for traceability, trend "
        "analysis, and debugging flaky tests."
    ),
    docs_note=(
        "Without `store_test_results`, test output is only available "
        "in the raw build log. Archiving test results enables CircleCI's "
        "test insights, timing-based splitting, and provides an audit "
        "trail that links each build to its test outcomes."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    has_store = False
    for _, job in iter_jobs(doc):
        for step in iter_steps(job):
            if isinstance(step, str) and step == "store_test_results":
                has_store = True
                break
            if isinstance(step, dict) and "store_test_results" in step:
                has_store = True
                break
        if has_store:
            break
    passed = has_store
    desc = (
        "At least one job archives test results via `store_test_results`."
        if passed else
        "No job uses `store_test_results`. Test output is only available "
        "in the raw build log, with no structured archival for "
        "traceability or trend analysis."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
