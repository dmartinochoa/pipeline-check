"""GLRUN-004. A fork pipeline minted a cloud OIDC token.

The GitLab analog of the ``runs`` provider's RUN-004, and the sharpest
escalation of GLRUN-002. A pipeline that both executed untrusted fork code
(GLRUN-002) and minted a cloud OIDC token means attacker-controlled code
reached cloud federation: it could exchange the GitLab CI ID token
(``id_tokens:``) for a federated AWS / GCP / Azure role and act with that
role's permissions. This is the run-history confirmation of a
fork-pipeline-to-cloud-credential breach.

Only meaningful under ``--audit-runs-logs``: the OIDC-mint signal is read
from the same fork-pipeline job traces GLRUN-003 already downloads, by
matching the cloud-federation call (AWS ``AssumeRoleWithWebIdentity``, GCP
``workloadIdentityPools``). Detection is tight (near-zero false positive)
but recall is best-effort, since trace content varies and masked variables
are redacted.
"""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import GitLabRunsContext, pipeline_resource, project_resource

RULE = Rule(
    id="GLRUN-004",
    title="Fork pipeline minted a cloud OIDC token",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    recommendation=(
        "Treat this as untrusted code that reached cloud federation: "
        "rotate / review the federated role's recent activity and assume "
        "the pipeline could act as that role. Restrict the cloud trust "
        "policy so a fork / merge-request ref cannot assume it (bind the "
        "subject to your protected branches and the project's own ID-token "
        "audience), and keep ``id_tokens:`` jobs out of fork merge-request "
        "pipelines."
    ),
    docs_note=(
        "Only evaluated with ``--audit-runs-logs``. Reuses the fork-pipeline "
        "job traces GLRUN-003 downloads and flags a fork pipeline whose "
        "trace shows cloud OIDC federation (AWS "
        "``AssumeRoleWithWebIdentity`` or GCP ``workloadIdentityPools``). "
        "Scoped to fork pipelines, so a trusted-branch pipeline that uses "
        "OIDC normally does not fire. Detection is high-precision but "
        "best-effort on recall (trace content varies; masked variables are "
        "redacted)."
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
                "to download and scan fork pipelines' job traces for cloud "
                "OIDC token minting."
            ),
            recommendation=RULE.recommendation,
            passed=True,
        )]
    if not ctx.oidc_mint_pipelines:
        return [Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=project_resource(ctx),
            description=(
                "No fork pipeline minted a cloud OIDC token in the scanned "
                "job traces."
            ),
            recommendation=RULE.recommendation,
            passed=True,
        )]
    by_id = {p.pipeline_id: p for p in ctx.fork_pipelines}
    findings: list[Finding] = []
    for pid in sorted(ctx.oidc_mint_pipelines):
        rec = by_id.get(pid)
        url = f" {rec.web_url}" if rec and rec.web_url else ""
        findings.append(Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=pipeline_resource(ctx, rec) if rec else project_resource(ctx),
            description=(
                f"Fork pipeline #{pid} minted a cloud OIDC token: untrusted "
                f"merge-request code reached cloud federation and could "
                f"assume the federated role.{url}".rstrip()
            ),
            recommendation=RULE.recommendation,
            passed=False,
        ))
    return findings
