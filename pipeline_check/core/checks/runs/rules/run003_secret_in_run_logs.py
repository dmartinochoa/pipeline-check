"""RUN-003. A secret-shaped string appeared in a workflow run's logs.

Only meaningful under ``--audit-runs-logs``, which downloads each
privileged-trigger run's log archive and scans the text with the shared
secret-shape catalog. GitHub masks registered Actions secrets in logs,
so a hit here is a credential that leaked *past* masking: a token a tool
printed, a value never registered as a secret, or a transformed
credential. That is the highest-signal log forensic, and on a fork PR
run (see RUN-001) it can be the breach itself. The token value is
redacted in the finding.
"""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import RunsContext, repo_resource, run_resource

RULE = Rule(
    id="RUN-003",
    title="Secret leaked in workflow run logs",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    cwe=("CWE-532",),
    recommendation=(
        "Rotate the leaked credential immediately, then stop it reaching "
        "the log: register it as an Actions secret so GitHub masks it, "
        "avoid `set -x` / `env` dumps in steps that hold it, and pipe "
        "tool output that may echo credentials through a redactor."
    ),
    docs_note=(
        "Only evaluated with ``--audit-runs-logs``. Downloads each "
        "privileged-trigger run's log archive (the Actions REST API "
        "``.../logs`` endpoint) and scans the text with the shared "
        "secret-shape catalog (``find_secret_values``). GitHub masks "
        "registered secrets, so a match is a credential that leaked past "
        "masking. The token value is redacted in the finding."
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
                "leaked secrets."
            ),
            recommendation=RULE.recommendation,
            passed=True,
        )]
    if not ctx.log_leaks:
        return [Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=repo_resource(ctx),
            description="No secret-shaped strings found in the scanned run logs.",
            recommendation=RULE.recommendation,
            passed=True,
        )]
    by_id = {r.run_id: r for r in ctx.runs}
    findings: list[Finding] = []
    for run_id, labels in sorted(ctx.log_leaks.items()):
        run = by_id.get(run_id)
        detectors = ", ".join(labels)
        where = (
            f"Run #{run_id} ({run.name or 'workflow'} on `{run.event}`"
            + (", from a fork" if run and run.from_fork else "")
            + ")"
            if run else f"Run #{run_id}"
        )
        url = f" {run.html_url}" if run and run.html_url else ""
        findings.append(Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=run_resource(ctx, run) if run else repo_resource(ctx),
            description=(
                f"{where} logged secret-shaped string(s): {detectors}. "
                f"GitHub masks registered secrets, so this leaked past "
                f"masking; rotate it.{url}".rstrip()
            ),
            recommendation=RULE.recommendation,
            passed=False,
        ))
    return findings
