"""RUN-004. A fork PR's run minted a cloud OIDC token.

The sharpest live escalation of RUN-001. A run that both executed
untrusted fork code on a privileged trigger *and* minted an OIDC token
means attacker-controlled code reached cloud federation: the run could
exchange the GitHub OIDC token for a federated AWS / GCP / Azure role
and act with that role's permissions. This is the static AC-016
(CI -> cloud OIDC trust) link confirmed as having actually happened, and
the run-history shape of a fork-PR-to-cloud-credential breach.

Only meaningful under ``--audit-runs-logs``: the OIDC-mint signal is
read from the same privileged-trigger run logs RUN-003 already downloads
(the GitHub OIDC issuer / token-request env, the AWS STS web-identity
call, GCP workload-identity federation). Detection is tight (near-zero
false positive) but recall is best-effort, since log content varies.
"""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import RunsContext, repo_resource, run_resource

RULE = Rule(
    id="RUN-004",
    title="Fork PR run minted a cloud OIDC token",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    cwe=("CWE-94",),
    recommendation=(
        "Treat this as untrusted code that reached cloud federation: "
        "rotate / review the federated role's recent activity and assume "
        "the run could act as that role. Restrict the role's trust policy "
        "so a fork / PR ref cannot assume it (pin the subject to your "
        "protected branches and environments), and move any "
        "OIDC-authenticated step out of the privileged ``pull_request_target`` "
        "/ ``workflow_run`` path that handles PR content (the "
        "label-then-deploy pattern)."
    ),
    docs_note=(
        "Only evaluated with ``--audit-runs-logs``. Reuses the "
        "privileged-trigger run logs RUN-003 downloads (the Actions REST "
        "API ``.../logs`` endpoint) and flags a run whose logs show OIDC "
        "token minting (``token.actions.githubusercontent.com``, the "
        "``ACTIONS_ID_TOKEN_REQUEST_*`` env, AWS "
        "``AssumeRoleWithWebIdentity``, or GCP ``workloadIdentityPools``). "
        "Scoped to fork-originated runs, so a trusted-branch deploy that "
        "uses OIDC normally does not fire. Detection is high-precision but "
        "best-effort on recall (log content varies; registered secrets "
        "are masked)."
    ),
)


def check(ctx: RunsContext) -> list[Finding]:
    if not ctx.logs_scanned:
        # Metadata-only run; don't imply the logs were checked.
        return [Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=repo_resource(ctx),
            description=(
                "Run-log scanning was not enabled; pass --audit-runs-logs "
                "to download and scan privileged-trigger run logs for "
                "fork runs that minted a cloud OIDC token."
            ),
            recommendation=RULE.recommendation,
            passed=True,
        )]
    by_id = {r.run_id: r for r in ctx.runs}
    fork_oidc = sorted(
        run_id for run_id in ctx.oidc_mint_runs
        if (run := by_id.get(run_id)) is not None and run.from_fork
    )
    if not fork_oidc:
        return [Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=repo_resource(ctx),
            description=(
                "No fork-originated run minted a cloud OIDC token in the "
                "scanned run logs."
            ),
            recommendation=RULE.recommendation,
            passed=True,
        )]
    findings: list[Finding] = []
    for run_id in fork_oidc:
        run = by_id[run_id]
        url = f" {run.html_url}" if run.html_url else ""
        findings.append(Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=run_resource(ctx, run),
            description=(
                f"Run #{run_id} ({run.name or 'workflow'} on `{run.event}`, "
                f"from fork `{run.head_repo or 'unknown'}`) minted a cloud "
                f"OIDC token: untrusted PR code reached cloud federation and "
                f"could assume the federated role.{url}".rstrip()
            ),
            recommendation=RULE.recommendation,
            passed=False,
        ))
    return findings
