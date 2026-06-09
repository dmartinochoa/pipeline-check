"""GLRUN-003. A secret-shaped string appeared in a fork pipeline's job trace.

The GitLab analog of the ``runs`` provider's RUN-003. Only meaningful under
``--audit-runs-logs``, which downloads each fork pipeline's job traces and
scans the text with the shared secret-shape catalog. GitLab masks CI/CD
variables marked "Masked" in job logs, so a hit here is a credential that
leaked *past* masking: a token a tool printed, a value never masked, or a
transformed credential. On a fork merge-request pipeline (see GLRUN-002),
that trace was produced by untrusted code, so the leak can be the breach
itself. The token value is redacted in the finding.
"""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import GitLabRunsContext, pipeline_resource, project_resource

RULE = Rule(
    id="GLRUN-003",
    title="Secret leaked in a fork pipeline's job trace",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    recommendation=(
        "Rotate the leaked credential immediately, then stop it reaching "
        "the trace: mark it a masked (and protected) CI/CD variable so "
        "GitLab redacts it, avoid ``set -x`` / ``env`` dumps in jobs that "
        "hold it, and pipe tool output that may echo credentials through a "
        "redactor. Keep protected variables away from fork merge-request "
        "pipelines entirely."
    ),
    docs_note=(
        "Only evaluated with ``--audit-runs-logs``. Downloads each resolved "
        "fork pipeline's job traces (the GitLab REST API "
        "``GET /projects/:id/jobs/:job_id/trace``) and scans the text with "
        "the shared secret-shape catalog (``find_secret_values``). GitLab "
        "masks marked variables, so a match is a credential that leaked "
        "past masking. Scoped to the fork pipelines GLRUN-002 resolves (the "
        "untrusted-code surface); the token value is redacted in the "
        "finding."
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
                "Job-trace scanning was not enabled; pass --audit-runs-logs "
                "to download and scan fork pipelines' job traces for leaked "
                "secrets."
            ),
            recommendation=RULE.recommendation,
            passed=True,
        )]
    if not ctx.trace_leaks:
        return [Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=project_resource(ctx),
            description=(
                "No secret-shaped strings found in the scanned fork pipeline "
                "job traces."
            ),
            recommendation=RULE.recommendation,
            passed=True,
        )]
    by_id = {p.pipeline_id: p for p in ctx.fork_pipelines}
    findings: list[Finding] = []
    for pid, labels in sorted(ctx.trace_leaks.items()):
        rec = by_id.get(pid)
        detectors = ", ".join(labels)
        url = f" {rec.web_url}" if rec and rec.web_url else ""
        findings.append(Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=pipeline_resource(ctx, rec) if rec else project_resource(ctx),
            description=(
                f"Fork pipeline #{pid} logged secret-shaped string(s): "
                f"{detectors}. GitLab masks marked variables, so this leaked "
                f"past masking; rotate it.{url}".rstrip()
            ),
            recommendation=RULE.recommendation,
            passed=False,
        ))
    return findings
