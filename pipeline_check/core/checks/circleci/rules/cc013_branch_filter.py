"""CC-013 — workflows should have branch filters on sensitive jobs."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_workflow_jobs
from ._helpers import DEPLOY_RE

RULE = Rule(
    id="CC-013",
    title="Deploy job in workflow has no branch filter",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-1",),
    esf=("ESF-C-APPROVAL",),
    cwe=("CWE-284",),
    recommendation=(
        "Add `filters.branches.only` to deploy-like workflow jobs so "
        "they only run on protected branches (e.g. main, release/*)."
    ),
    docs_note=(
        "Without branch filters, a deploy job triggers on every branch "
        "push, including feature branches and forks. Restricting "
        "sensitive jobs to specific branches limits the blast radius "
        "of a compromised commit."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    unfiltered: list[str] = []
    for _wf_name, job_name, job_cfg in iter_workflow_jobs(doc):
        if not DEPLOY_RE.search(job_name):
            continue
        filters = job_cfg.get("filters") or {}
        branches = filters.get("branches") if isinstance(filters, dict) else None
        if not branches:
            unfiltered.append(job_name)
    passed = not unfiltered
    desc = (
        "All deploy-like workflow jobs have branch filters, or no "
        "deploy-like jobs exist."
        if passed else
        f"{len(unfiltered)} deploy-like workflow job(s) lack branch "
        f"filters: {', '.join(unfiltered[:5])}"
        f"{'...' if len(unfiltered) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
