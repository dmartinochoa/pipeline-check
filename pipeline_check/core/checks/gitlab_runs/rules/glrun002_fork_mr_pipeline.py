"""GLRUN-002. A fork merge request's pipeline executed (untrusted code ran).

The high-severity subset of GLRUN-001 and the GitLab analog of the ``runs``
provider's RUN-001. A merge request opened from a *fork* (its source
project differs from the target project) had a pipeline run in this
project's CI, so attacker-controllable code executed here. When the
project enables "Run pipelines for fork merge requests" and (worse) exposes
protected CI/CD variables or a privileged runner to them, that pipeline can
read the project's secrets and push to its registry / environments. This is
the GitLab face of the pwn-request / poisoned-pipeline class, confirmed
from run history rather than inferred from ``.gitlab-ci.yml``.

Only evaluated under ``--audit-runs-logs`` (the deep run-forensics pass):
GitLab's pipeline list doesn't carry the source/target project, so
fork-origin is resolved via the MR API (list merge requests, keep the ones
whose ``source_project_id`` differs from the ``target_project_id``, pull
each such MR's pipelines). Detection is exact (GitLab's own MR-to-project
linkage); recall is bounded to the most recent fork merge requests.
"""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import GitLabRunsContext, pipeline_resource, project_resource

RULE = Rule(
    id="GLRUN-002",
    title="Fork merge-request pipeline executed in run history",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    recommendation=(
        "Treat fork merge-request pipelines as running untrusted code. "
        "Require a project member to approve fork-MR pipelines before they "
        "run (the 'Pipelines must be approved' setting), keep protected "
        "CI/CD variables and protected runners away from them, and run "
        "fork-MR jobs on isolated, ephemeral runners with no standing cloud "
        "credentials. If fork-MR pipelines are not needed, disable 'Run "
        "pipelines for fork merge requests'."
    ),
    docs_note=(
        "Only evaluated with ``--audit-runs-logs``. Resolves fork-origin "
        "via the GitLab MR API: lists recent merge requests, keeps those "
        "whose ``source_project_id`` differs from the ``target_project_id`` "
        "(a fork), and pulls each such MR's pipelines "
        "(``/merge_requests/:iid/pipelines``). Each fork pipeline ran "
        "untrusted code in this project's CI. Independent of GLRUN-001's "
        "metadata pass; the fork-MR fetch is bounded to the most recent "
        "fork merge requests."
    ),
)


def check(ctx: GitLabRunsContext) -> list[Finding]:
    if not ctx.forks_resolved:
        # Metadata-only run; don't imply fork-origin was checked.
        return [Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=project_resource(ctx),
            description=(
                "Fork-origin resolution was not enabled; pass "
                "--audit-runs-logs to resolve which merge-request pipelines "
                "came from a fork (untrusted code)."
            ),
            recommendation=RULE.recommendation,
            passed=True,
        )]
    if not ctx.fork_pipelines:
        return [Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=project_resource(ctx),
            description=(
                "No fork merge-request pipelines were found in the resolved "
                "merge requests."
            ),
            recommendation=RULE.recommendation,
            passed=True,
        )]
    findings: list[Finding] = []
    for rec in sorted(ctx.fork_pipelines, key=lambda r: r.pipeline_id):
        url = f" {rec.web_url}" if rec.web_url else ""
        findings.append(Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=pipeline_resource(ctx, rec),
            description=(
                f"Pipeline #{rec.pipeline_id} (ref `{rec.ref or '?'}`, "
                f"source `{rec.source or '?'}`) ran for a fork merge "
                f"request: untrusted fork code executed in this project's "
                f"CI.{url}".rstrip()
            ),
            recommendation=RULE.recommendation,
            passed=False,
        ))
    return findings
