"""CC-009 — Deploy-like workflow jobs should have a manual approval gate."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_workflow_jobs
from ._helpers import DEPLOY_RE

RULE = Rule(
    id="CC-009",
    title="Deploy job missing manual approval gate",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-1",),
    esf=("ESF-C-APPROVAL", "ESF-C-ENV-SEP"),
    cwe=("CWE-284",),
    recommendation=(
        "Add a `type: approval` job that precedes the deploy job in "
        "the workflow, and list it in the deploy job's `requires:`. "
        "This ensures a human must click Approve in the CircleCI UI "
        "before production changes roll out."
    ),
    docs_note=(
        "In CircleCI, manual approval is implemented by adding a job "
        "with `type: approval` to the workflow and making the deploy "
        "job require it. Without this gate, any push to the triggering "
        "branch deploys immediately with no human review."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    ungated: list[str] = []
    # Build a per-workflow map of approval job names.
    workflows = doc.get("workflows") or {}
    if not isinstance(workflows, dict):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="No workflows declared in the config.",
            recommendation="No action required.", passed=True,
        )
    for wf_name, job_name, job_cfg in iter_workflow_jobs(doc):
        if not DEPLOY_RE.search(job_name):
            continue
        # The deploy job itself might be an approval type.
        if job_cfg.get("type") == "approval":
            continue
        # Check if any of the job's `requires:` entries are approval jobs.
        requires = job_cfg.get("requires") or []
        if not isinstance(requires, list):
            requires = [requires]
        # Collect all approval job names in this workflow.
        approval_jobs: set[str] = set()
        for _, other_name, other_cfg in iter_workflow_jobs(doc):
            if other_cfg.get("type") == "approval":
                approval_jobs.add(other_name)
        if any(req in approval_jobs for req in requires):
            continue
        ungated.append(f"{wf_name}/{job_name}")
    passed = not ungated
    desc = (
        "Every deploy job is gated by a manual approval step."
        if passed else
        f"{len(ungated)} deploy job(s) have no manual approval gate: "
        f"{', '.join(ungated)}. Without an approval step, any push to "
        f"the triggering branch deploys immediately with no human review."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
