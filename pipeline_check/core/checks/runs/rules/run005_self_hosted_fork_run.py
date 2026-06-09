"""RUN-005. A fork PR's run executed on a self-hosted runner.

GitHub's most-warned-about self-hosted-runner risk, confirmed live. A
fork PR runs attacker-controlled code, and on a self-hosted runner that
code executes on infrastructure the repo owner controls: arbitrary
command execution on the runner host, a foothold to pivot into the
internal network, and (because self-hosted runners are not
ephemeral by default) persistence that poisons later jobs. This holds
even on an unprivileged ``pull_request`` trigger that carries no secrets,
so it is independent of RUN-001 (privileged-trigger fork runs).

Only meaningful under ``--audit-runs-logs``: the runner type appears
per job (the Actions REST API ``.../jobs`` endpoint), not in the run
list, and GitHub labels every self-hosted runner's jobs ``self-hosted``.
Fork-run job metadata is fetched bounded; detection is exact (the label
is unambiguous), recall is bounded to the most recent fork runs.
"""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import RunsContext, repo_resource, run_resource

RULE = Rule(
    id="RUN-005",
    title="Fork PR run executed on a self-hosted runner",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    cwe=("CWE-94",),
    recommendation=(
        "Do not run fork pull-request code on self-hosted runners. Set the "
        "repository / org policy to require approval for first-time (and "
        "ideally all) outside-contributor workflow runs, and run any "
        "fork-triggered job on GitHub-hosted ephemeral runners instead. If "
        "self-hosted runners are required, isolate them (ephemeral / "
        "single-use VMs, a locked-down network, no standing cloud "
        "credentials) and scope them to trusted workflows only."
    ),
    docs_note=(
        "Only evaluated with ``--audit-runs-logs``. Fetches job metadata "
        "(the Actions REST API ``.../jobs`` endpoint) for recent "
        "fork-originated runs and flags any whose jobs ran on a self-hosted "
        "runner (GitHub adds the ``self-hosted`` label to every such "
        "runner). Independent of the trigger, so it catches a plain fork "
        "``pull_request`` run on your own infrastructure. The fork-run "
        "fetch is bounded to the most recent runs."
    ),
)


def check(ctx: RunsContext) -> list[Finding]:
    if not ctx.logs_scanned:
        # Metadata-only run; don't imply the job runners were checked.
        return [Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=repo_resource(ctx),
            description=(
                "Job-runner auditing was not enabled; pass --audit-runs-logs "
                "to fetch fork-run job metadata and flag fork code that ran "
                "on a self-hosted runner."
            ),
            recommendation=RULE.recommendation,
            passed=True,
        )]
    if not ctx.self_hosted_runs:
        return [Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=repo_resource(ctx),
            description=(
                "No fork-originated run executed on a self-hosted runner in "
                "the audited runs."
            ),
            recommendation=RULE.recommendation,
            passed=True,
        )]
    by_id = {r.run_id: r for r in ctx.runs}
    findings: list[Finding] = []
    for run_id, labels in sorted(ctx.self_hosted_runs.items()):
        run = by_id.get(run_id)
        url = f" {run.html_url}" if run and run.html_url else ""
        fork = f"`{run.head_repo or 'unknown'}`" if run else "a fork"
        findings.append(Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=run_resource(ctx, run) if run else repo_resource(ctx),
            description=(
                f"Run #{run_id} ("
                + (f"{run.name or 'workflow'} on `{run.event}`, " if run else "")
                + f"from fork {fork}) executed on a self-hosted runner "
                f"({labels}): untrusted PR code ran on infrastructure you "
                f"control.{url}".rstrip()
            ),
            recommendation=RULE.recommendation,
            passed=False,
        ))
    return findings
