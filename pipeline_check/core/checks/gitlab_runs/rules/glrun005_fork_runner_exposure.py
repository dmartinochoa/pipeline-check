"""GLRUN-005. A fork pipeline ran on a self-managed runner.

The GitLab analog of the ``runs`` provider's RUN-005. A fork merge-request
pipeline executes untrusted contributor code; when its jobs run on a
self-managed (non-shared) runner, that code executes on infrastructure the
project / group owner operates: arbitrary command execution on the runner
host, a foothold to pivot into the internal network, and (because
self-managed runners are not ephemeral by default) persistence that can
poison later jobs. This holds regardless of whether the pipeline carried
secrets or minted an OIDC token, so it is independent of GLRUN-003 /
GLRUN-004.

Only meaningful under ``--audit-runs-logs``: the executing runner appears
in each job's metadata (the jobs API embeds ``runner``), which the
fork-pipeline deep pass already fetches. GitLab.com's shared
(``instance_type``) runners are ephemeral and not flagged; only
``is_shared: false`` (``project_type`` / ``group_type``) runners are.
Detection reads metadata, not the trace, so it works even when the
fetcher can't download traces. Recall is bounded to the most recent fork
pipelines.
"""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import GitLabRunsContext, pipeline_resource, project_resource

RULE = Rule(
    id="GLRUN-005",
    title="Fork pipeline ran on a self-managed runner",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    recommendation=(
        "Do not run fork merge-request code on self-managed runners. In the "
        "project / group CI settings, disable shared-and-specific runners for "
        "fork MR pipelines, or require maintainer approval before a pipeline "
        "runs for a fork merge request, and run fork-triggered pipelines on "
        "ephemeral shared runners instead. If self-managed runners are "
        "required, isolate them (single-use VMs, a locked-down network, no "
        "standing cloud credentials) and tag them so only trusted pipelines "
        "target them."
    ),
    docs_note=(
        "Only evaluated with ``--audit-runs-logs``. Reads the ``runner`` "
        "embedded in each fork-pipeline job (the same ``/jobs`` page "
        "GLRUN-003 / GLRUN-004 list) and flags a fork pipeline whose jobs "
        "ran on a self-managed runner (``is_shared: false``, i.e. a "
        "``project_type`` / ``group_type`` runner the owner operates). "
        "GitLab.com ``instance_type`` shared runners are ephemeral and not "
        "flagged. Independent of secrets / OIDC, so it catches a plain fork "
        "MR pipeline that merely executed on your own infrastructure. The "
        "fork-pipeline fetch is bounded to the most recent pipelines."
    ),
)


def check(ctx: GitLabRunsContext) -> list[Finding]:
    if not ctx.forks_resolved:
        return [Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=project_resource(ctx),
            description=(
                "Job-runner auditing was not enabled; pass --audit-runs-logs "
                "to fetch fork-pipeline job metadata and flag fork code that "
                "ran on a self-managed runner."
            ),
            recommendation=RULE.recommendation,
            passed=True,
        )]
    if not ctx.self_managed_runner_pipelines:
        return [Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=project_resource(ctx),
            description=(
                "No fork pipeline ran on a self-managed runner in the audited "
                "pipelines."
            ),
            recommendation=RULE.recommendation,
            passed=True,
        )]
    by_id = {p.pipeline_id: p for p in ctx.fork_pipelines}
    findings: list[Finding] = []
    for pid, runners in sorted(ctx.self_managed_runner_pipelines.items()):
        rec = by_id.get(pid)
        url = f" {rec.web_url}" if rec and rec.web_url else ""
        names = ", ".join(runners)
        findings.append(Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=pipeline_resource(ctx, rec) if rec else project_resource(ctx),
            description=(
                f"Fork pipeline #{pid} ran on a self-managed runner ({names}): "
                f"untrusted merge-request code executed on infrastructure you "
                f"operate.{url}".rstrip()
            ),
            recommendation=RULE.recommendation,
            passed=False,
        ))
    return findings
