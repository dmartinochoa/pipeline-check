"""RUN-001. A fork PR's code actually executed on a privileged trigger.

Forensic counterpart to the static pwn-request rules (GHA-002 / GHA-046):
the static pack flags a workflow that *could* run untrusted PR content
in a privileged context; this fires when the Actions run history shows
it *did*. A run whose ``event`` is a privileged trigger
(``pull_request_target`` / ``workflow_run``) and whose ``head_repository``
is a fork is untrusted code that executed with the base repository's
secrets and a write-scoped ``GITHUB_TOKEN`` -- the live shape of the
tj-actions/changed-files (CVE-2025-30066) and GhostAction incidents,
which were visible in run history before anyone read the workflow.
"""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import (
    PRIVILEGED_TRIGGERS,
    RunsContext,
    repo_resource,
    run_resource,
)

RULE = Rule(
    id="RUN-001",
    title="Fork PR executed on a privileged trigger",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    cwe=("CWE-94",),
    recommendation=(
        "Treat each flagged run as untrusted-code execution in a "
        "privileged context. Confirm the workflow that ran does not "
        "check out and execute the PR head, and move any build-from-PR "
        "logic into a separate unprivileged ``pull_request`` workflow "
        "(the label-then-build pattern). Rotate any secret the run "
        "could read if the workflow is not demonstrably safe."
    ),
    docs_note=(
        "Sourced from the GitHub Actions REST API "
        "(``GET /repos/{owner}/{repo}/actions/runs``). A run is flagged "
        "when its ``event`` is a privileged trigger "
        "(``pull_request_target`` / ``workflow_run``) and its "
        "``head_repository`` is a fork (or differs from the base "
        "repository). Unlike the static GHA-002 check this is evidence "
        "the dangerous path actually ran, so it survives even when the "
        "workflow file has since been deleted or rewritten."
    ),
)


def check(ctx: RunsContext) -> list[Finding]:
    offending = [
        r for r in ctx.runs
        if r.event in PRIVILEGED_TRIGGERS and r.from_fork
    ]
    if not offending:
        return [Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=repo_resource(ctx),
            description=(
                "No fork-originated runs on a privileged trigger in the "
                f"{len(ctx.runs)} most recent run(s)."
            ),
            recommendation=RULE.recommendation,
            passed=True,
        )]
    return [
        Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=run_resource(ctx, r),
            description=(
                f"Run #{r.run_id} ({r.name or 'workflow'}) fired on "
                f"`{r.event}` from fork `{r.head_repo or 'unknown'}` "
                f"(actor {r.actor or 'unknown'}, {r.created_at or 'n/a'}). "
                "Untrusted fork code ran with the base repository's "
                f"secrets. {r.html_url}".rstrip()
            ),
            recommendation=RULE.recommendation,
            passed=False,
        )
        for r in offending
    ]
