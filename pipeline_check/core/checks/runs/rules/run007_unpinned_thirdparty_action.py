"""RUN-007. A third-party action pinned by a mutable tag ran with secrets.

The preventive twin of RUN-006. Where RUN-006 confirms a *known-compromised*
action executed (an IOC match), this flags the exposure *before* it becomes
an incident: a third-party action a privileged run resolved from a mutable
ref (a tag like ``@v4`` or a branch, not a 40-hex commit SHA) actually
executed with the run's secrets and ``GITHUB_TOKEN`` in scope. If the
upstream force-moves that tag, the next privileged run silently pulls the
attacker's code, which is exactly how the tj-actions/changed-files
(CVE-2025-30066) and the 2026 Trivy / Checkmarx campaigns spread.

This is the run-forensics pin-hygiene signal. A static ``uses:`` scan flags
unpinned references in the workflow file, but the ``runs`` provider audits a
repo purely from its run history (it never reads the workflow), and the run
log records what the action *resolved to* at execution time, including
actions pulled transitively (a composite action's own dependencies) or via a
reusable / dynamically-built ``uses:`` that the file-level scan cannot see.
First-party (``actions`` / ``github``) and the repo's own actions are not
flagged, only genuinely third-party code.

Only meaningful under ``--audit-runs-logs`` and scoped to the
privileged-trigger runs RUN-003 / RUN-004 already download (the
secret-bearing surface), so the signal stays high. Recall is bounded to the
runs whose logs were fetched; the pinned-vs-mutable test is exact.
"""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import RunsContext, repo_resource, run_resource

RULE = Rule(
    id="RUN-007",
    title="Third-party action pinned by a mutable tag executed in a privileged run",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3", "CICD-SEC-4"),
    cwe=("CWE-829", "CWE-1357"),
    recommendation=(
        "Pin every third-party action to a full commit SHA rather than a "
        "tag or branch, which the upstream (or an attacker who compromises "
        "it) can force-move (the tj-actions/changed-files lesson). Use the "
        "resolved SHA the run log records as the pin, after confirming it is "
        "a known-good release, and consider Dependabot to bump the pinned "
        "SHAs. Restricting which actions can run at all (an allow-list) "
        "shrinks the third-party surface further."
    ),
    docs_note=(
        "Only evaluated with ``--audit-runs-logs``. Reuses the "
        "privileged-trigger run logs RUN-003 / RUN-004 download and inspects "
        "GitHub's ``Download action repository 'owner/repo@ref' (SHA:...)`` "
        "lines: a third-party action (not ``actions`` / ``github`` and not "
        "the repo's own owner) whose ``@ref`` is a mutable tag or branch "
        "rather than a 40-hex commit SHA is flagged, with the resolved SHA "
        "carried as evidence. The preventive twin of RUN-006: RUN-006 "
        "confirms a known-compromised action ran, RUN-007 flags the "
        "repoint-able third-party actions that could be the next one. "
        "Scoped to the secret-bearing privileged runs (not the bounded "
        "non-privileged RUN-006 pass), so the signal stays high; recall is "
        "bounded to the fetched runs."
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
                "Run-log scanning was not enabled; pass --audit-runs-logs to "
                "download and scan privileged-trigger run logs for "
                "third-party actions pinned by a mutable tag."
            ),
            recommendation=RULE.recommendation,
            passed=True,
        )]
    if not ctx.unpinned_action_runs:
        return [Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=repo_resource(ctx),
            description=(
                "No third-party action pinned by a mutable tag was found "
                "executing in the scanned privileged-trigger run logs."
            ),
            recommendation=RULE.recommendation,
            passed=True,
        )]
    by_id = {r.run_id: r for r in ctx.runs}
    findings: list[Finding] = []
    for run_id, labels in sorted(ctx.unpinned_action_runs.items()):
        run = by_id.get(run_id)
        url = f" {run.html_url}" if run and run.html_url else ""
        joined = ", ".join(labels)
        findings.append(Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=run_resource(ctx, run) if run else repo_resource(ctx),
            description=(
                f"Run #{run_id} ("
                + (f"{run.name or 'workflow'} on `{run.event}`, " if run else "")
                + f"resolved {len(labels)} third-party action(s) from a "
                f"mutable tag/branch instead of a commit SHA: {joined}. The "
                f"run carried secrets, so a force-moved tag would run "
                f"attacker code with those credentials. Pin to the resolved "
                f"SHA.{url}".rstrip()
            ),
            recommendation=RULE.recommendation,
            passed=False,
        ))
    return findings
