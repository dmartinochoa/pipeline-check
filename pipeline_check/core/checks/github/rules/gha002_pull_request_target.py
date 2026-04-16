"""GHA-002 — pull_request_target must not check out the PR head."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps, workflow_triggers
from ._helpers import PR_HEAD_REF_RE


RULE = Rule(
    id="GHA-002",
    title="pull_request_target checks out PR head",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION", "ESF-D-BUILD-ENV"),
    recommendation=(
        "Use `pull_request` instead of `pull_request_target` for any "
        "workflow that must run untrusted code. If you need write "
        "scope, split the workflow: a `pull_request_target` job that "
        "labels the PR, and a separate `pull_request`-triggered job "
        "that builds it with read-only secrets."
    ),
    docs_note=(
        "`pull_request_target` runs with a write-scope GITHUB_TOKEN "
        "and access to repository secrets — deliberately so, since "
        "it's how labelling and comment-bot workflows work. When the "
        "same workflow then explicitly checks out the PR head "
        "(`ref: ${{ github.event.pull_request.head.sha }}` or `.ref`) "
        "it executes attacker-controlled code with those privileges."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    if "pull_request_target" not in workflow_triggers(doc):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="Workflow is not triggered by pull_request_target.",
            recommendation="No action required.", passed=True,
        )
    offending: list[str] = []
    for job_id, job in iter_jobs(doc):
        for idx, step in enumerate(iter_steps(job)):
            uses = step.get("uses")
            if not isinstance(uses, str) or not uses.startswith("actions/checkout@"):
                continue
            ref = ((step.get("with") or {}).get("ref") or "")
            if isinstance(ref, str) and PR_HEAD_REF_RE.search(ref):
                offending.append(f"{job_id}[{idx}]")
    passed = not offending
    desc = (
        "pull_request_target workflow does not check out untrusted PR head code."
        if passed else
        f"pull_request_target workflow explicitly checks out the PR head "
        f"ref in steps: {', '.join(offending)}. This executes attacker-"
        f"controlled code with a write-scope GITHUB_TOKEN and access to "
        f"repository secrets."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
