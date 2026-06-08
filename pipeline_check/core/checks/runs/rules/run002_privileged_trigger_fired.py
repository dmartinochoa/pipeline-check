"""RUN-002. A privileged trigger actually fired (attack surface is live).

Aggregate forensic signal: how many recent runs executed on a
privileged trigger (``pull_request_target`` / ``workflow_run``),
regardless of fork origin. Even trusted-branch runs on these triggers
mean the pwn-request surface is exercised in production. This is
awareness/context, not a vulnerability on its own, so it sits at MEDIUM
and defers the high-severity case (untrusted fork code) to RUN-001.
"""
from __future__ import annotations

from collections import Counter

from ...base import Finding, Severity
from ...rule import Rule
from ..base import PRIVILEGED_TRIGGERS, RunsContext, repo_resource

RULE = Rule(
    id="RUN-002",
    title="Privileged trigger exercised in run history",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-4",),
    recommendation=(
        "Review the workflows that run on these triggers and confirm "
        "none check out or execute PR-controlled content while holding "
        "secrets. See RUN-001 for any of these runs that came from a "
        "fork (the high-severity subset)."
    ),
    docs_note=(
        "Sourced from the Actions REST API. Counts recent runs whose "
        "``event`` is ``pull_request_target`` or ``workflow_run``. This "
        "is forensic context (the surface is live in production), which "
        "the static config scan cannot confirm on its own."
    ),
)


def check(ctx: RunsContext) -> list[Finding]:
    counts = Counter(
        r.event for r in ctx.runs if r.event in PRIVILEGED_TRIGGERS
    )
    if not counts:
        return [Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=repo_resource(ctx),
            description=(
                "No privileged-trigger runs in the "
                f"{len(ctx.runs)} most recent run(s)."
            ),
            recommendation=RULE.recommendation,
            passed=True,
        )]
    summary = ", ".join(f"{ev}={n}" for ev, n in sorted(counts.items()))
    return [Finding(
        check_id=RULE.id,
        title=RULE.title,
        severity=RULE.severity,
        resource=repo_resource(ctx),
        description=(
            f"{sum(counts.values())} recent run(s) fired on a privileged "
            f"trigger ({summary}). The pwn-request attack surface is "
            "exercised in production; audit those workflows for "
            "PR-controlled content handling."
        ),
        recommendation=RULE.recommendation,
        passed=False,
    )]
